"""
LANL Comprehensive, Multi-Source Cyber-Security Events Dataset Loader.

Parses the LANL auth.txt file and loads authentication events into Neo4j
using the two-phase CREATE pattern described in Section V-A of the paper:

  Phase 1 (sequential): Pre-materialize all unique Host nodes via MERGE.
  Phase 2 (parallel):   Create edges via MATCH + CREATE to bypass lock contention.

Reference: Listing 1 in the paper.
"""

import csv
import logging
import time
from pathlib import Path
from typing import Optional

from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


def parse_auth_line(line: str) -> Optional[dict]:
    """Parse a single line from LANL auth.txt.

    Format: time,src_user@src_domain,dst_user@dst_domain,src_computer,dst_computer,auth_type,logon_type,auth_orient,success_failure

    Returns:
        Dictionary with parsed fields, or None if line is malformed.
    """
    parts = line.strip().split(",")
    if len(parts) < 9:
        return None

    return {
        "ts": int(parts[0]),
        "src_user": parts[1],
        "dst_user": parts[2],
        "src_host": parts[3],
        "dst_host": parts[4],
        "auth_type": parts[5],
        "logon_type": parts[6],
        "auth_orient": parts[7],
        "success": parts[8],
    }


def load_lanl_auth(
    auth_path: str,
    neo4j_uri: str = "neo4j://localhost:7687",
    neo4j_user: str = "neo4j",
    neo4j_password: str = "password",
    batch_size: int = 5000,
    max_edges: Optional[int] = None,
):
    """Load LANL auth.txt into Neo4j using the two-phase CREATE pattern.

    Args:
        auth_path: Path to LANL auth.txt file.
        neo4j_uri: Neo4j bolt URI.
        neo4j_user: Neo4j username.
        neo4j_password: Neo4j password.
        batch_size: Number of edges per batch in Phase 2.
        max_edges: Maximum number of edges to load (None = all).
    """
    auth_path = Path(auth_path)
    if not auth_path.exists():
        raise FileNotFoundError(f"LANL auth.txt not found at {auth_path}")

    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

    logger.info("Phase 1: Extracting unique hosts for sequential vertex pre-materialization...")
    t0 = time.time()

    hosts = set()
    edge_count = 0
    with open(auth_path) as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 5:
                continue
            hosts.add(row[3])  # src_host
            hosts.add(row[4])  # dst_host
            edge_count += 1
            if max_edges and edge_count >= max_edges:
                break

    host_list = list(hosts)
    logger.info(f"  Found {len(host_list)} unique hosts from {edge_count} edges.")

    # Phase 1: Sequential MERGE for all host nodes (Listing 1, lines 1-3)
    phase1_query = """
    UNWIND $hosts AS h
    MERGE (:Host {id: h})
    """

    with driver.session() as session:
        # Process in chunks to avoid memory issues
        chunk_size = 10000
        for i in range(0, len(host_list), chunk_size):
            chunk = host_list[i : i + chunk_size]
            session.run(phase1_query, hosts=chunk)

    t1 = time.time()
    logger.info(f"  Phase 1 completed in {t1 - t0:.1f}s.")

    # Phase 2: Parallel edge creation via MATCH + CREATE (Listing 1, lines 5-8)
    logger.info("Phase 2: Parallel edge generation (MATCH + CREATE)...")

    phase2_query = """
    UNWIND $edges AS e
    MATCH (s:Host {id: e.src}), (d:Host {id: e.dst})
    CREATE (s)-[:AUTH {ts: e.ts, type: e.type}]->(d)
    """

    batch = []
    edges_written = 0

    with open(auth_path) as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 9:
                continue

            batch.append(
                {
                    "src": row[3],
                    "dst": row[4],
                    "ts": int(row[0]),
                    "type": row[5],
                }
            )

            if len(batch) >= batch_size:
                with driver.session() as session:
                    session.run(phase2_query, edges=batch)
                edges_written += len(batch)
                batch = []

                if edges_written % 50000 == 0:
                    elapsed = time.time() - t1
                    rate = edges_written / elapsed if elapsed > 0 else 0
                    logger.info(f"  {edges_written:,} edges written ({rate:,.0f} edges/s)")

                if max_edges and edges_written >= max_edges:
                    break

    # Flush remaining batch
    if batch:
        with driver.session() as session:
            session.run(phase2_query, edges=batch)
        edges_written += len(batch)

    t2 = time.time()
    total_time = t2 - t0
    logger.info(
        f"Phase 2 completed. Total: {edges_written:,} edges in {total_time:.1f}s "
        f"({edges_written / total_time:,.0f} edges/s)"
    )

    driver.close()
    return edges_written


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Load LANL auth.txt into Neo4j")
    parser.add_argument("--auth-path", default="data/lanl/auth.txt")
    parser.add_argument("--neo4j-uri", default="neo4j://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", default="password")
    parser.add_argument("--batch-size", type=int, default=5000)
    parser.add_argument("--max-edges", type=int, default=None)
    args = parser.parse_args()

    load_lanl_auth(
        args.auth_path,
        args.neo4j_uri,
        args.neo4j_user,
        args.neo4j_password,
        args.batch_size,
        args.max_edges,
    )
