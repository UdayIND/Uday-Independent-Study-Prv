#!/usr/bin/env python3
"""
SENTINEL-RL Ingestion Benchmark — Reproduces Table II and Figure 2.

Measures ingestion wall time for the two-phase CREATE pattern vs. the
single-phase MERGE baseline at varying edge counts.

Usage:
    python scripts/ingest_lanl.py --auth-path data/lanl/auth.txt
"""

import argparse
import logging
import time

from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Edge counts from Table II
EDGE_COUNTS = [100_000, 500_000, 1_000_000, 5_000_000, 10_000_000, 24_000_000]


def load_edges(auth_path: str, max_edges: int) -> tuple[list[str], list[dict]]:
    """Load edges from auth.txt up to max_edges."""
    hosts = set()
    edges = []

    with open(auth_path) as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 9:
                continue
            src, dst = parts[3], parts[4]
            hosts.add(src)
            hosts.add(dst)
            edges.append({"src": src, "dst": dst, "ts": int(parts[0]), "type": parts[5]})
            if len(edges) >= max_edges:
                break

    return list(hosts), edges


def benchmark_two_phase(
    driver, hosts: list[str], edges: list[dict], batch_size: int = 5000
) -> float:
    """Run two-phase CREATE ingestion and return wall time."""
    # Clear database
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")

    t0 = time.time()

    # Phase 1: Sequential vertex pre-materialization
    phase1_query = "UNWIND $hosts AS h MERGE (:Host {id: h})"
    with driver.session() as session:
        for i in range(0, len(hosts), 10000):
            session.run(phase1_query, hosts=hosts[i : i + 10000])

    # Phase 2: Parallel edge creation
    phase2_query = """
    UNWIND $edges AS e
    MATCH (s:Host {id: e.src}), (d:Host {id: e.dst})
    CREATE (s)-[:AUTH {ts: e.ts, type: e.type}]->(d)
    """
    with driver.session() as session:
        for i in range(0, len(edges), batch_size):
            session.run(phase2_query, edges=edges[i : i + batch_size])

    return time.time() - t0


def benchmark_single_phase(driver, edges: list[dict], batch_size: int = 5000) -> float:
    """Run single-phase MERGE ingestion and return wall time."""
    # Clear database
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")

    t0 = time.time()

    merge_query = """
    UNWIND $edges AS e
    MERGE (s:Host {id: e.src})
    MERGE (d:Host {id: e.dst})
    MERGE (s)-[:AUTH {ts: e.ts, type: e.type}]->(d)
    """
    with driver.session() as session:
        for i in range(0, len(edges), batch_size):
            session.run(merge_query, edges=edges[i : i + batch_size])

    return time.time() - t0


def main():
    parser = argparse.ArgumentParser(description="SENTINEL-RL Ingestion Benchmark")
    parser.add_argument("--auth-path", default="data/lanl/auth.txt")
    parser.add_argument("--neo4j-uri", default="neo4j://localhost:7687")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", default="password")
    parser.add_argument("--edge-counts", nargs="+", type=int, default=[100_000])
    args = parser.parse_args()

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))

    print("\n" + "=" * 70)
    print("SENTINEL-RL Ingestion Benchmark (Table II)")
    print("=" * 70)
    print(f"{'Edge Count':>12} | {'MERGE (s)':>10} | {'CREATE (s)':>10} | {'Speedup':>8}")
    print("-" * 50)

    for count in args.edge_counts:
        logger.info(f"Loading {count:,} edges from {args.auth_path}...")
        hosts, edges = load_edges(args.auth_path, count)

        if len(edges) < count:
            logger.warning(f"Only {len(edges):,} edges available (requested {count:,})")

        # Benchmark two-phase CREATE
        create_time = benchmark_two_phase(driver, hosts, edges)

        # Benchmark single-phase MERGE (skip for very large counts)
        if count <= 1_000_000:
            merge_time = benchmark_single_phase(driver, edges)
            speedup = merge_time / create_time if create_time > 0 else 0
        else:
            merge_time = float("nan")
            speedup = float("nan")

        print(f"{count:>12,} | {merge_time:>10.1f} | {create_time:>10.1f} | {speedup:>7.1f}×")

    driver.close()
    print("=" * 70)


if __name__ == "__main__":
    main()
