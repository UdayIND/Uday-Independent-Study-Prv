#!/usr/bin/env python3
"""Utility script to validate PCAP file before processing."""

import argparse
import sys
from pathlib import Path


def validate_pcap(pcap_path: Path) -> bool:
    """Validate PCAP file exists and is readable.

    Args:
        pcap_path: Path to PCAP file

    Returns:
        True if valid, False otherwise
    """
    if not pcap_path.exists():
        print(f"Error: PCAP file not found: {pcap_path}", file=sys.stderr)
        return False

    if not pcap_path.is_file():
        print(f"Error: Path is not a file: {pcap_path}", file=sys.stderr)
        return False

    # Check file size
    file_size = pcap_path.stat().st_size
    if file_size == 0:
        print(f"Warning: PCAP file is empty: {pcap_path}", file=sys.stderr)
        return False

    # Check file extension
    if pcap_path.suffix not in [".pcap", ".pcapng"]:
        print(f"Warning: File extension is not .pcap or .pcapng: {pcap_path}", file=sys.stderr)

    print(f"PCAP file validated: {pcap_path} ({file_size} bytes)")
    return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Validate PCAP file")
    parser.add_argument("pcap", type=str, help="Path to PCAP file")

    args = parser.parse_args()
    pcap_path = Path(args.pcap)

    if validate_pcap(pcap_path):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
