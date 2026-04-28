"""
SENTINEL-RL Telemetry Ingestion Plane
Real-time, fault-tolerant streaming ingestion from Kafka (with File Fallback) to Neo4j.
"""

import json
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Callable, Optional

import requests

try:
    from confluent_kafka import Consumer, KafkaError, KafkaException

    HAS_KAFKA = True
except ImportError:
    HAS_KAFKA = False
    Consumer = None
    KafkaError = None
    KafkaException = None
from neo4j import GraphDatabase
from neo4j import exceptions as neo4j_exc


# ==========================================
# CONFIGURATION
# ==========================================
class Config:
    KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
    KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "network_events")
    KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "sentinel_ingestion_group")

    NEO4J_URI = os.getenv("NEO4J_URI", "neo4j://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

    WEBHOOK_URL = os.getenv("WEBHOOK_URL", "http://localhost:8000/trigger_investigation")

    FALLBACK_LOG_FILE = os.getenv("FALLBACK_LOG_FILE", "/var/log/suricata/eve.json")

    BATCH_SIZE = int(os.getenv("BATCH_SIZE", "500"))
    BATCH_TIMEOUT_SEC = float(os.getenv("BATCH_TIMEOUT", "1.0"))

    ALERT_WINDOW_SEC = int(os.getenv("ALERT_WINDOW_SEC", "10"))
    ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "25"))  # Paper: N=25


# ==========================================
# OBSERVABILITY & LOGGING
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("sentinel.ingestion")


# ==========================================
# GRAPH TRANSFORMER
# ==========================================
class GraphTransformer:
    """Transforms raw JSON telemetry into formatted payloads for Neo4j UNWIND."""

    @staticmethod
    def parse_event(raw_payload: str) -> Optional[dict[str, Any]]:
        try:
            data = json.loads(raw_payload)

            src_ip = data.get("src_ip")
            dst_ip = data.get("dst_ip")
            if not src_ip or not dst_ip:
                return None  # Drop malformed events lacking routing data

            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "user": data.get("user", "UNKNOWN"),
                "action": data.get("event_type", data.get("action", "CONNECT")).upper(),
                "timestamp": data.get("timestamp", data.get("ts", time.time())),
                "raw_event": raw_payload,
            }
        except json.JSONDecodeError:
            logger.debug("Dropped malformed JSON event")
            return None
        except Exception as e:
            logger.error(f"Transformation error: {e}")
            return None


# ==========================================
# NEO4J WRITER (CIRCUIT BREAKER + BATCH)
# ==========================================
class Neo4jWriter:
    """Manages connection pool, handles retries, and executes micro-batch UNWIND operations."""

    def __init__(self, uri_override=None):
        self.uri = uri_override or Config.NEO4J_URI
        self.driver = GraphDatabase.driver(
            self.uri, auth=(Config.NEO4J_USER, Config.NEO4J_PASSWORD), max_connection_pool_size=50
        )
        self.circuit_open = False
        self._verify_connection()

    def _verify_connection(self):
        try:
            self.driver.verify_connectivity()
            logger.info("Connected successfully to Neo4j cluster.")
            self.circuit_open = False
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j at startup: {e}")
            self.circuit_open = True

    def write_batch(self, events: list[dict[str, Any]]) -> bool:
        if not events:
            return True

        if self.circuit_open:
            logger.warning("Neo4j Circuit Breaker Open. Dropping/DLQing batch.")
            return False

        # Phase 1: Sequential Vertex Pre-materialization (avoid lock contention)
        query_phase_1 = """
        UNWIND $events AS event
        MERGE (src:Host {ip: event.src_ip})
        MERGE (dst:Host {ip: event.dst_ip})
        MERGE (u:User {username: event.user})
        """

        # Phase 2: Parallel Edge Generation (using explicit CREATE to bypass locks)
        query_phase_2 = """
        UNWIND $events AS event
        MATCH (src:Host {ip: event.src_ip}), (dst:Host {ip: event.dst_ip}), (u:User {username: event.user})
        CREATE (src)-[c:CONNECTED_TO {
            first_seen: event.timestamp,
            last_seen: event.timestamp,
            count: 1
        }]->(dst)
        CREATE (u)-[a:PERFORMED {
            type: event.action,
            first_seen: event.timestamp,
            last_seen: event.timestamp,
            count: 1
        }]->(dst)
        """

        retries = 3
        backoff = 1.0

        for attempt in range(retries):
            try:
                with self.driver.session() as session:
                    session.run(query_phase_1, events=events)
                    session.run(query_phase_2, events=events)
                return True
            except (neo4j_exc.TransientError, neo4j_exc.SessionExpired, OSError) as e:
                logger.warning(f"Neo4j write failed (attempt {attempt+1}/{retries}): {e}")
                time.sleep(backoff)
                backoff *= 2
            except Exception as e:
                logger.error(f"Fatal Neo4j operational error: {e}")
                break

        # If we reach here, retries failed
        self.circuit_open = True
        logger.error("Neo4j Circuit Breaker Tripped.")
        threading.Timer(30.0, self._verify_connection).start()  # Auto-reset attempt in 30s
        return False

    def close(self):
        self.driver.close()


# ==========================================
# REAL-TIME ALERT ENGINE
# ==========================================
class AlertEngine:
    """Maintains a sliding timeline of events per node and triggers actionable webhooks."""

    def __init__(self):
        # Maps node_id (e.g., src_ip) to a deque of timestamps
        self.window = defaultdict(deque)
        self.lock = threading.Lock()
        logger.info(
            f"Alert Engine initialized (Threshold: {Config.ALERT_THRESHOLD} evts / {Config.ALERT_WINDOW_SEC}s)"
        )

    def process_events(self, events: list[dict[str, Any]]):
        now = time.time()
        cutoff = now - Config.ALERT_WINDOW_SEC

        alerts_to_trigger = []

        with self.lock:
            for event in events:
                src_ip = event["src_ip"]
                self.window[src_ip].append(now)

                # Evict stale events
                while self.window[src_ip] and self.window[src_ip][0] < cutoff:
                    self.window[src_ip].popleft()

                # Check threshold
                if len(self.window[src_ip]) >= Config.ALERT_THRESHOLD:
                    alerts_to_trigger.append((src_ip, len(self.window[src_ip])))
                    self.window[src_ip].clear()  # Reset to avoid alert-storming

        for node_id, count in alerts_to_trigger:
            self.trigger_webhook(node_id, count)

    def trigger_webhook(self, node_id: str, count: int):
        payload = {
            "node_id": node_id,
            "event_count": count,
            "time_window": Config.ALERT_WINDOW_SEC,
            "recent_activity_summary": "High frequency connection/auth anomalies detected.",
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            response = requests.post(Config.WEBHOOK_URL, json=payload, timeout=2.0)
            if response.status_code == 200:
                logger.info(
                    f"🚨 ALERT DISPATCHED: Node {node_id} exceeded threshold ({count} events)."
                )
            else:
                logger.warning(f"Webhook rejected payload. Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to dispatch alert webhook for {node_id}: {e}")


# ==========================================
# INGESTION SOURCING (KAFKA & FILE)
# ==========================================
class FileWatcherFallback:
    """Tail-like behavior for local log files if Kafka goes entirely offline."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.running = False

    def consume_generator(self):
        if not os.path.exists(self.filepath):
            logger.error(f"Fallback file not found: {self.filepath}")
            return

        self.running = True
        with open(self.filepath) as f:
            f.seek(0, 2)  # Jump to end of file
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line

    def stop(self):
        self.running = False


class KafkaConsumerManager:
    """Robust Kafka subscriber with manual offset management and rebalance callbacks."""

    def __init__(self):
        conf = {
            "bootstrap.servers": Config.KAFKA_BROKER,
            "group.id": Config.KAFKA_GROUP_ID,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,  # Manual committing for AT LEAST ONCE processing
            "session.timeout.ms": 6000,
        }
        self.consumer = Consumer(conf)
        self.running = False

    def on_assign(self, consumer, partitions):
        logger.info(f"Kafka Partitions Assigned: {partitions}")

    def on_revoke(self, consumer, partitions):
        logger.warning(f"Kafka Partitions Revoked: {partitions}")

    def start(self, message_callback: Callable[[list[str]], None]):
        """Starts the consumer loop with micro-batching logic."""
        try:
            self.consumer.subscribe(
                [Config.KAFKA_TOPIC], on_assign=self.on_assign, on_revoke=self.on_revoke
            )
            self.running = True

            logger.info("Starting Kafka Consumption loop...")
            batch = []
            last_flush = time.time()

            while self.running:
                msg = self.consumer.poll(timeout=0.1)

                if msg is None:
                    # Flush if timeout reached and batch has items
                    if batch and (time.time() - last_flush) >= Config.BATCH_TIMEOUT_SEC:
                        if message_callback(batch):
                            self.consumer.commit(asynchronous=False)
                        batch = []
                        last_flush = time.time()
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    else:
                        logger.error(f"Kafka error: {msg.error()}")
                        raise KafkaException(msg.error())

                # Valid Message Received
                raw_payload = msg.value().decode("utf-8")
                batch.append(raw_payload)

                if len(batch) >= Config.BATCH_SIZE:
                    if message_callback(batch):
                        self.consumer.commit(asynchronous=False)
                    batch = []
                    last_flush = time.time()

        except KafkaException as e:
            logger.error(f"Kafka Fatal Error: {e}")
            self.initiate_fallback(message_callback)
        finally:
            self.stop()

    def initiate_fallback(self, message_callback: Callable[[list[str]], None]):
        logger.warning("FAILOVER ACTIVATED: Transitioning to local FileWatcher fallback.")
        fallback = FileWatcherFallback(Config.FALLBACK_LOG_FILE)

        batch = []
        last_flush = time.time()

        for raw_payload in fallback.consume_generator():
            if not self.running:
                break

            batch.append(raw_payload)
            if (
                len(batch) >= Config.BATCH_SIZE
                or (time.time() - last_flush) >= Config.BATCH_TIMEOUT_SEC
            ):
                if batch:
                    message_callback(batch)
                    batch = []
                    last_flush = time.time()

    def stop(self):
        self.running = False
        if self.consumer:
            self.consumer.close()
            logger.info("Kafka consumer shut down gracefully.")


# ==========================================
# PIPELINE ORCHESTRATOR
# ==========================================
class IngestionPipeline:
    def __init__(self):
        self.writer = Neo4jWriter()
        self.alert_engine = AlertEngine()
        self.consumer_manager = KafkaConsumerManager()

    def process_batch(self, raw_messages: list[str]) -> bool:
        """Core pipeline step combining transformer, alerts, and DB writing."""
        start_time = time.time()

        processed_events = []
        for raw in raw_messages:
            event = GraphTransformer.parse_event(raw)
            if event:
                processed_events.append(event)

        if not processed_events:
            return True

        # Pipeline Stage 1: Async Alert Evaluation (Memory Operations)
        self.alert_engine.process_events(processed_events)

        # Pipeline Stage 2: Synchronous DB Write
        success = self.writer.write_batch(processed_events)

        if success:
            duration = time.time() - start_time
            logger.info(
                f"Processed batch of {len(processed_events)} events in {duration:.3f}s. "
                f"({len(processed_events)/duration:.1f} evts/sec)"
            )
        else:
            # Drop/DLQ strategy -> in production, push failed `raw_messages` to a Redpanda/Kafka DLQ topic here.
            pass

        return success

    def run(self):
        def signal_handler(sig, frame):
            logger.info("Received termination signal. Shutting down...")
            self.consumer_manager.stop()
            self.writer.close()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Blocking call
        self.consumer_manager.start(self.process_batch)


# ==========================================
# ENTRY POINT
# ==========================================
if __name__ == "__main__":
    logger.info("Initializing SENTINEL-RL Real-Time Ingestion Plane...")
    pipeline = IngestionPipeline()
    pipeline.run()
