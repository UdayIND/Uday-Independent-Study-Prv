#!/usr/bin/env python3
"""Generate synthetic PCAPs for deterministic testing and benchmarking.

Creates three PCAPs:
  - synthetic_scan.pcap:   Port scanning (one source -> 120+ destinations)
  - synthetic_beacon.pcap: DNS beaconing (repeated queries to C2 domain)
  - synthetic_benign.pcap: Normal web browsing + DNS traffic
"""

import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

try:
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, RandShort, wrpcap
except ImportError:
    logger.error(
        "scapy is required. Install with: pip install scapy\n"
        "Or: . venv/bin/activate && pip install scapy"
    )
    sys.exit(1)

OUTPUT_DIR = Path("data/raw/synthetic")


def generate_scan_pcap(output_path: Path) -> None:
    """Generate a port scanning PCAP.

    Simulates one attacker IP scanning 120+ destination IPs on common ports.
    """
    packets = []
    attacker_ip = "10.200.1.50"
    base_ts = 1705312200.0  # 2024-01-15T10:30:00 UTC

    # Scan 130 unique destination IPs across ports 22, 80, 443
    for i in range(130):
        dst_ip = f"192.168.{i // 256}.{i % 256 + 1}"
        for port in [22, 80, 443]:
            pkt = (
                Ether()
                / IP(src=attacker_ip, dst=dst_ip)
                / TCP(sport=RandShort(), dport=port, flags="S")
            )
            pkt.time = base_ts + (i * 0.5) + (port * 0.01)
            packets.append(pkt)

    # Add some RST responses (failed connections)
    for i in range(0, 130, 3):
        dst_ip = f"192.168.{i // 256}.{i % 256 + 1}"
        pkt = (
            Ether()
            / IP(src=dst_ip, dst=attacker_ip)
            / TCP(sport=80, dport=RandShort(), flags="RA")
        )
        pkt.time = base_ts + (i * 0.5) + 0.1
        packets.append(pkt)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated scan PCAP: {output_path} ({len(packets)} packets)")


def generate_beacon_pcap(output_path: Path) -> None:
    """Generate a DNS beaconing PCAP.

    Simulates an infected host repeatedly querying a C2 domain every ~30 seconds.
    """
    packets = []
    infected_ip = "10.100.5.20"
    dns_server = "8.8.8.8"
    c2_domain = "update.evil-c2-server.xyz"
    base_ts = 1705312200.0

    # 40 beaconing queries over ~20 minutes (every 30 seconds)
    for i in range(40):
        # DNS query to C2 domain
        pkt = (
            Ether()
            / IP(src=infected_ip, dst=dns_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=c2_domain))
        )
        pkt.time = base_ts + (i * 30)
        packets.append(pkt)

        # DNS response
        resp = (
            Ether()
            / IP(src=dns_server, dst=infected_ip)
            / UDP(sport=53, dport=RandShort())
            / DNS(
                qr=1,
                qd=DNSQR(qname=c2_domain),
            )
        )
        resp.time = base_ts + (i * 30) + 0.05
        packets.append(resp)

    # Also query a few sub-domains (data exfiltration pattern)
    for i in range(15):
        exfil_domain = f"data{i:04d}.evil-c2-server.xyz"
        pkt = (
            Ether()
            / IP(src=infected_ip, dst=dns_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=exfil_domain))
        )
        pkt.time = base_ts + 1200 + (i * 5)
        packets.append(pkt)

    # Add some normal DNS queries to mix
    normal_domains = ["www.google.com", "api.github.com", "cdn.example.org"]
    for i, domain in enumerate(normal_domains):
        pkt = (
            Ether()
            / IP(src=infected_ip, dst=dns_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain))
        )
        pkt.time = base_ts + (i * 120)
        packets.append(pkt)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated beacon PCAP: {output_path} ({len(packets)} packets)")


def generate_benign_pcap(output_path: Path) -> None:
    """Generate a benign traffic PCAP.

    Normal web browsing and DNS traffic with no scanning or beaconing patterns.
    """
    packets = []
    client_ip = "10.50.1.10"
    dns_server = "8.8.8.8"
    base_ts = 1705312200.0

    # Normal DNS queries to various domains (spread out, low repetition)
    domains = [
        "www.google.com",
        "mail.google.com",
        "docs.google.com",
        "www.github.com",
        "api.github.com",
        "www.stackoverflow.com",
        "cdn.jsdelivr.net",
        "fonts.googleapis.com",
        "www.wikipedia.org",
        "en.wikipedia.org",
        "www.reddit.com",
        "i.redd.it",
    ]
    for i, domain in enumerate(domains):
        pkt = (
            Ether()
            / IP(src=client_ip, dst=dns_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain))
        )
        pkt.time = base_ts + (i * 180)  # Every 3 minutes
        packets.append(pkt)

    # Normal HTTP connections to a few web servers
    web_servers = [
        ("142.250.80.46", 80),   # google
        ("140.82.121.4", 443),   # github
        ("151.101.1.69", 443),   # reddit
    ]
    for i in range(20):
        server_ip, port = web_servers[i % len(web_servers)]
        # SYN
        syn = (
            Ether()
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=RandShort(), dport=port, flags="S")
        )
        syn.time = base_ts + (i * 120)
        packets.append(syn)
        # SYN-ACK
        sa = (
            Ether()
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=port, dport=RandShort(), flags="SA")
        )
        sa.time = base_ts + (i * 120) + 0.05
        packets.append(sa)
        # Complete 3-way handshake
        ack = (
            Ether()
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=syn[TCP].sport, dport=port, flags="A")
        )
        ack.time = sa.time + 0.01
        packets.append(ack)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated benign PCAP: {output_path} ({len(packets)} packets)")


def generate_mixed_pcap(output_path: Path) -> None:
    """Generate a mixed traffic PCAP with both benign and malicious activity.

    Contains normal browsing traffic from multiple hosts plus one attacker
    performing a port scan. Ground truth: attacker_ip=10.200.1.50 does recon_scanning.
    """
    packets = []
    attacker_ip = "10.200.1.50"
    normal_clients = ["10.50.1.10", "10.50.1.11", "10.50.1.12"]
    dns_server = "8.8.8.8"
    base_ts = 1705312200.0

    # Normal traffic from multiple clients
    domains = ["www.google.com", "mail.google.com", "www.github.com", "cdn.example.org"]
    web_servers = [("142.250.80.46", 80), ("140.82.121.4", 443)]

    for client_idx, client_ip in enumerate(normal_clients):
        # DNS queries
        for i, domain in enumerate(domains):
            pkt = (
                Ether()
                / IP(src=client_ip, dst=dns_server)
                / UDP(sport=RandShort(), dport=53)
                / DNS(rd=1, qd=DNSQR(qname=domain))
            )
            pkt.time = base_ts + (client_idx * 60) + (i * 200)
            packets.append(pkt)

        # HTTP connections
        for i in range(10):
            server_ip, port = web_servers[i % len(web_servers)]
            syn = (
                Ether()
                / IP(src=client_ip, dst=server_ip)
                / TCP(sport=RandShort(), dport=port, flags="S")
            )
            syn.time = base_ts + (client_idx * 60) + (i * 150)
            packets.append(syn)
            sa = (
                Ether()
                / IP(src=server_ip, dst=client_ip)
                / TCP(sport=port, dport=RandShort(), flags="SA")
            )
            sa.time = base_ts + (client_idx * 60) + (i * 150) + 0.05
            packets.append(sa)
            # Complete 3-way handshake
            ack = (
                Ether()
                / IP(src=client_ip, dst=server_ip)
                / TCP(sport=syn[TCP].sport, dport=port, flags="A")
            )
            ack.time = sa.time + 0.01
            packets.append(ack)

    # Malicious scan embedded in normal traffic
    for i in range(80):
        dst_ip = f"192.168.{i // 256}.{i % 256 + 1}"
        for port in [22, 80, 443]:
            pkt = (
                Ether()
                / IP(src=attacker_ip, dst=dst_ip)
                / TCP(sport=RandShort(), dport=port, flags="S")
            )
            pkt.time = base_ts + 300 + (i * 0.8) + (port * 0.01)
            packets.append(pkt)

    # RST responses to attacker
    for i in range(0, 80, 2):
        dst_ip = f"192.168.{i // 256}.{i % 256 + 1}"
        pkt = (
            Ether()
            / IP(src=dst_ip, dst=attacker_ip)
            / TCP(sport=80, dport=RandShort(), flags="RA")
        )
        pkt.time = base_ts + 300 + (i * 0.8) + 0.1
        packets.append(pkt)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated mixed PCAP: {output_path} ({len(packets)} packets)")


def generate_dns_exfil_pcap(output_path: Path) -> None:
    """Generate a DNS exfiltration PCAP.

    Simulates data exfiltration via high-entropy subdomain queries to a single
    domain, mixed with normal DNS traffic. Ground truth: src=10.100.5.20 does
    dns_beaconing to exfil.malware-domain.net.
    """
    import hashlib

    packets = []
    infected_ip = "10.100.5.20"
    normal_client = "10.50.1.10"
    dns_server = "8.8.8.8"
    base_ts = 1705312200.0
    exfil_domain = "exfil.malware-domain.net"

    # Normal DNS from uninfected client
    normal_domains = [
        "www.google.com", "mail.google.com", "www.github.com",
        "cdn.jsdelivr.net", "api.stripe.com", "www.wikipedia.org",
    ]
    for i, domain in enumerate(normal_domains):
        pkt = (
            Ether()
            / IP(src=normal_client, dst=dns_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain))
        )
        pkt.time = base_ts + (i * 300)
        packets.append(pkt)

    # Exfiltration: high-entropy subdomain queries
    for i in range(50):
        # Simulate encoded data as subdomain
        data_chunk = hashlib.md5(f"chunk_{i}".encode()).hexdigest()[:16]
        query_domain = f"{data_chunk}.{exfil_domain}"
        pkt = (
            Ether()
            / IP(src=infected_ip, dst=dns_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=query_domain))
        )
        pkt.time = base_ts + (i * 30)  # Every 30s
        packets.append(pkt)

        # DNS response (NXDOMAIN for most - exfil data not real domains)
        resp = (
            Ether()
            / IP(src=dns_server, dst=infected_ip)
            / UDP(sport=53, dport=RandShort())
            / DNS(
                qr=1,
                rcode=3,  # NXDOMAIN
                qd=DNSQR(qname=query_domain),
            )
        )
        resp.time = base_ts + (i * 30) + 0.03
        packets.append(resp)

    # Also periodic beaconing queries from infected host
    for i in range(20):
        pkt = (
            Ether()
            / IP(src=infected_ip, dst=dns_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=exfil_domain))
        )
        pkt.time = base_ts + (i * 60) + 15  # Every 60s offset
        packets.append(pkt)

    # Normal DNS from infected host too (to make detection harder)
    for i, domain in enumerate(normal_domains[:3]):
        pkt = (
            Ether()
            / IP(src=infected_ip, dst=dns_server)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain))
        )
        pkt.time = base_ts + (i * 600)
        packets.append(pkt)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated DNS exfil PCAP: {output_path} ({len(packets)} packets)")


def generate_multi_attacker_pcap(output_path: Path) -> None:
    """Generate a multi-attacker PCAP with 3 simultaneous attackers.

    Attacker A: Fast scan on 192.168.1.0/24 (ports 22, 80, 443)
    Attacker B: Slow scan on 192.168.2.0/24 (port 3389)
    Attacker C: DNS beaconing to c2.evil.com with high entropy subdomains
    Plus normal background traffic from 5 legitimate hosts.
    """
    import hashlib
    import random

    random.seed(42)
    packets = []
    base_ts = 1705312200.0

    attacker_a = "10.200.1.50"
    attacker_b = "10.200.2.75"
    attacker_c = "10.100.3.30"
    dns_server = "8.8.8.8"
    normal_hosts = ["10.50.1.10", "10.50.1.11", "10.50.1.12", "10.50.1.13", "10.50.1.14"]

    # Attacker A: Fast scan of 30 hosts on 3 ports (90 SYNs)
    for i in range(30):
        dst_ip = f"192.168.1.{i + 1}"
        for port in [22, 80, 443]:
            pkt = Ether() / IP(src=attacker_a, dst=dst_ip) / TCP(sport=RandShort(), dport=port, flags="S")
            pkt.time = base_ts + (i * 0.3) + (port * 0.005)
            packets.append(pkt)
        # RST from some targets
        if i % 2 == 0:
            rst = Ether() / IP(src=dst_ip, dst=attacker_a) / TCP(sport=80, dport=RandShort(), flags="RA")
            rst.time = base_ts + (i * 0.3) + 0.1
            packets.append(rst)

    # Attacker B: Slow scan of 25 hosts on RDP port with jitter
    for i in range(25):
        dst_ip = f"192.168.2.{i + 1}"
        jitter = random.uniform(0, 5)
        pkt = Ether() / IP(src=attacker_b, dst=dst_ip) / TCP(sport=RandShort(), dport=3389, flags="S")
        pkt.time = base_ts + 60 + (i * 8) + jitter
        packets.append(pkt)

    # Attacker C: DNS beaconing with high-entropy subdomains
    c2_domain = "c2.evil.com"
    for i in range(35):
        data_hash = hashlib.md5(f"exfil_{i}".encode()).hexdigest()[:12]
        query = f"{data_hash}.{c2_domain}"
        pkt = Ether() / IP(src=attacker_c, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=query))
        pkt.time = base_ts + (i * 25) + random.uniform(0, 3)
        packets.append(pkt)
        # NXDOMAIN response
        resp = Ether() / IP(src=dns_server, dst=attacker_c) / UDP(sport=53, dport=RandShort()) / DNS(qr=1, rcode=3, qd=DNSQR(qname=query))
        resp.time = pkt.time + 0.05
        packets.append(resp)

    # Normal background traffic from 5 hosts
    web_servers = [("142.250.80.46", 443), ("140.82.121.4", 443), ("151.101.1.69", 80)]
    normal_domains = ["www.google.com", "mail.google.com", "api.github.com", "www.stackoverflow.com"]
    for host in normal_hosts:
        for i in range(8):
            server_ip, port = web_servers[i % len(web_servers)]
            syn = Ether() / IP(src=host, dst=server_ip) / TCP(sport=RandShort(), dport=port, flags="S")
            syn.time = base_ts + random.uniform(0, 800)
            packets.append(syn)
            sa = Ether() / IP(src=server_ip, dst=host) / TCP(sport=port, dport=RandShort(), flags="SA")
            sa.time = syn.time + 0.05
            packets.append(sa)
            # Complete 3-way handshake
            ack = Ether() / IP(src=host, dst=server_ip) / TCP(sport=syn[TCP].sport, dport=port, flags="A")
            ack.time = sa.time + 0.01
            packets.append(ack)
        for i in range(3):
            domain = normal_domains[i % len(normal_domains)]
            dns_pkt = Ether() / IP(src=host, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            dns_pkt.time = base_ts + random.uniform(0, 800)
            packets.append(dns_pkt)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated multi-attacker PCAP: {output_path} ({len(packets)} packets)")


def generate_killchain_pcap(output_path: Path) -> None:
    """Generate a kill chain PCAP: recon -> beaconing -> lateral movement.

    Single attacker progressing through attack phases over 30 minutes.
    """
    import hashlib
    import random

    random.seed(43)
    packets = []
    attacker_ip = "10.200.5.100"
    dns_server = "8.8.8.8"
    c2_domain = "updates.legit-looking.com"
    base_ts = 1705312200.0

    # Phase 1: Recon (0-10 min) - scan 20 hosts
    for i in range(20):
        dst_ip = f"192.168.10.{i + 1}"
        for port in [22, 80, 443, 8080]:
            pkt = Ether() / IP(src=attacker_ip, dst=dst_ip) / TCP(sport=RandShort(), dport=port, flags="S")
            pkt.time = base_ts + (i * 3) + (port * 0.01) + random.uniform(0, 0.5)
            packets.append(pkt)
        if i % 3 == 0:
            rst = Ether() / IP(src=dst_ip, dst=attacker_ip) / TCP(sport=80, dport=RandShort(), flags="RA")
            rst.time = base_ts + (i * 3) + 0.2
            packets.append(rst)

    # Phase 2: C2 beaconing (10-20 min) - periodic DNS queries
    for i in range(20):
        pkt = Ether() / IP(src=attacker_ip, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=c2_domain))
        pkt.time = base_ts + 600 + (i * 30) + random.uniform(0, 2)
        packets.append(pkt)
        # Also exfil subdomains
        data = hashlib.md5(f"data_{i}".encode()).hexdigest()[:10]
        exfil_pkt = Ether() / IP(src=attacker_ip, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=f"{data}.{c2_domain}"))
        exfil_pkt.time = pkt.time + 2
        packets.append(exfil_pkt)

    # Phase 3: Lateral movement (20-30 min) - connections to internal hosts on unusual ports
    internal_targets = [f"192.168.10.{i}" for i in [3, 7, 12, 15, 19]]
    unusual_ports = [4444, 5555, 8443, 9090, 1337]
    for i, (target, port) in enumerate(zip(internal_targets, unusual_ports)):
        syn = Ether() / IP(src=attacker_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="S")
        syn.time = base_ts + 1200 + (i * 60) + random.uniform(0, 5)
        packets.append(syn)
        sa = Ether() / IP(src=target, dst=attacker_ip) / TCP(sport=port, dport=RandShort(), flags="SA")
        sa.time = syn.time + 0.05
        packets.append(sa)
        # Complete 3-way handshake
        ack = Ether() / IP(src=attacker_ip, dst=target) / TCP(sport=syn[TCP].sport, dport=port, flags="A")
        ack.time = sa.time + 0.01
        packets.append(ack)

    # Background noise: normal traffic
    normal_host = "10.50.1.10"
    for i in range(15):
        pkt = Ether() / IP(src=normal_host, dst="142.250.80.46") / TCP(sport=RandShort(), dport=443, flags="S")
        pkt.time = base_ts + random.uniform(0, 1800)
        packets.append(pkt)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated killchain PCAP: {output_path} ({len(packets)} packets)")


def generate_slow_scan_pcap(output_path: Path) -> None:
    """Generate a slow/low-and-slow scan PCAP.

    Scanner sends 1 connection every 30-60 seconds with jitter.
    Mixed with heavy legitimate traffic to test signal-to-noise.
    """
    import random

    random.seed(44)
    packets = []
    scanner_ip = "10.200.9.5"
    dns_server = "8.8.8.8"
    base_ts = 1705312200.0

    # Slow scan: 40 targets over 30 minutes (1 per ~45s with jitter)
    for i in range(40):
        dst_ip = f"172.16.{i // 256}.{i % 256 + 1}"
        port = [22, 80, 443, 8080, 3306][i % 5]
        delay = random.uniform(30, 60)
        pkt = Ether() / IP(src=scanner_ip, dst=dst_ip) / TCP(sport=RandShort(), dport=port, flags="S")
        pkt.time = base_ts + sum(random.uniform(30, 60) for _ in range(i))
        packets.append(pkt)
        # Some RSTs
        if random.random() < 0.4:
            rst = Ether() / IP(src=dst_ip, dst=scanner_ip) / TCP(sport=port, dport=RandShort(), flags="RA")
            rst.time = pkt.time + 0.1
            packets.append(rst)

    # Heavy normal traffic (10x the scan traffic) from 8 hosts
    normal_hosts = [f"10.50.1.{i}" for i in range(10, 18)]
    web_servers = [("142.250.80.46", 443), ("140.82.121.4", 443), ("151.101.1.69", 80), ("104.16.132.229", 443)]
    normal_domains = ["www.google.com", "api.github.com", "cdn.cloudflare.com", "www.reddit.com", "docs.python.org"]

    for host in normal_hosts:
        for i in range(50):
            server_ip, port = web_servers[i % len(web_servers)]
            syn = Ether() / IP(src=host, dst=server_ip) / TCP(sport=RandShort(), dport=port, flags="S")
            syn.time = base_ts + random.uniform(0, 1800)
            packets.append(syn)
            sa = Ether() / IP(src=server_ip, dst=host) / TCP(sport=port, dport=RandShort(), flags="SA")
            sa.time = syn.time + 0.03
            packets.append(sa)
            # Complete 3-way handshake
            ack = Ether() / IP(src=host, dst=server_ip) / TCP(sport=syn[TCP].sport, dport=port, flags="A")
            ack.time = sa.time + 0.01
            packets.append(ack)
        for i in range(5):
            domain = normal_domains[i % len(normal_domains)]
            dns_pkt = Ether() / IP(src=host, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            dns_pkt.time = base_ts + random.uniform(0, 1800)
            packets.append(dns_pkt)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated slow scan PCAP: {output_path} ({len(packets)} packets)")


def generate_noisy_benign_pcap(output_path: Path) -> None:
    """Generate a noisy benign PCAP that resembles malicious patterns.

    Tests false positive resilience:
    - Web server receiving connections from many clients (looks like fan-out)
    - DNS resolver with many unique domain lookups (looks like beaconing)
    - CDN traffic with periodic health checks (looks like C2)
    """
    import random

    random.seed(45)
    packets = []
    dns_server = "8.8.8.8"
    base_ts = 1705312200.0

    # Pattern 1: Web server receiving many connections from few clients (high volume, low fan-out)
    # 10 clients x 6 connections each = 60 total connections but only 10 unique destinations
    # This stays below the fan_out_threshold (15) while maintaining high traffic volume
    web_server = "10.50.1.100"
    for i in range(10):
        client_ip = f"203.0.113.{i + 1}"
        for j in range(6):
            syn = Ether() / IP(src=client_ip, dst=web_server) / TCP(sport=RandShort(), dport=80, flags="S")
            syn.time = base_ts + random.uniform(0, 600)
            packets.append(syn)
            sa = Ether() / IP(src=web_server, dst=client_ip) / TCP(sport=80, dport=RandShort(), flags="SA")
            sa.time = syn.time + 0.02
            packets.append(sa)
            # Complete 3-way handshake
            ack = Ether() / IP(src=client_ip, dst=web_server) / TCP(sport=syn[TCP].sport, dport=80, flags="A")
            ack.time = sa.time + 0.01
            packets.append(ack)

    # Pattern 2: DNS resolver with many unique domains (looks like beaconing)
    resolver = "10.50.1.200"
    unique_domains = [
        f"subdomain{i}.example{j}.com" for i in range(20) for j in range(3)
    ]
    for i, domain in enumerate(unique_domains[:50]):
        pkt = Ether() / IP(src=resolver, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        pkt.time = base_ts + (i * 15) + random.uniform(0, 5)
        packets.append(pkt)

    # Pattern 3: CDN health checks - periodic connections (looks like C2)
    cdn_monitor = "10.50.1.50"
    cdn_endpoints = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    for i in range(30):
        for endpoint in cdn_endpoints:
            pkt = Ether() / IP(src=cdn_monitor, dst=endpoint) / TCP(sport=RandShort(), dport=443, flags="S")
            pkt.time = base_ts + (i * 60) + random.uniform(0, 2)
            packets.append(pkt)

    # Regular browsing from other hosts
    browsers = ["10.50.1.10", "10.50.1.11"]
    for host in browsers:
        for i in range(20):
            pkt = Ether() / IP(src=host, dst="142.250.80.46") / TCP(sport=RandShort(), dport=443, flags="S")
            pkt.time = base_ts + random.uniform(0, 1800)
            packets.append(pkt)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated noisy benign PCAP: {output_path} ({len(packets)} packets)")


def generate_evasion_ip_rotation_pcap(output_path: Path) -> None:
    """Evasion test: distributed scan across 5 rotating source IPs.

    Each scanner targets only 12 unique destinations (below fan_out_threshold=15).
    Total coverage: 60 unique targets, but per-IP detection should miss this.
    Tests whether the detector can identify coordinated distributed scans.
    """
    import random

    random.seed(50)
    packets = []
    base_ts = 1705312200.0

    scanner_ips = [f"10.200.3.{i+1}" for i in range(5)]
    dns_server = "8.8.8.8"
    normal_hosts = ["10.50.1.10", "10.50.1.11", "10.50.1.12"]

    # Each scanner hits 12 unique destinations (below fan_out_threshold of 15)
    for idx, scanner in enumerate(scanner_ips):
        for i in range(12):
            dst_ip = f"192.168.{idx}.{i + 1}"
            for port in [22, 80, 443]:
                pkt = Ether() / IP(src=scanner, dst=dst_ip) / TCP(sport=RandShort(), dport=port, flags="S")
                pkt.time = base_ts + (idx * 120) + (i * 2) + (port * 0.01) + random.uniform(0, 0.5)
                packets.append(pkt)
            # Some RSTs
            if i % 3 == 0:
                rst = Ether() / IP(src=dst_ip, dst=scanner) / TCP(sport=80, dport=RandShort(), flags="RA")
                rst.time = base_ts + (idx * 120) + (i * 2) + 0.1
                packets.append(rst)

    # Normal background traffic
    web_servers = [("142.250.80.46", 443), ("140.82.121.4", 443)]
    for host in normal_hosts:
        for i in range(15):
            server_ip, port = web_servers[i % len(web_servers)]
            sport = RandShort()._fix()
            syn = Ether() / IP(src=host, dst=server_ip) / TCP(sport=sport, dport=port, flags="S")
            syn.time = base_ts + random.uniform(0, 600)
            packets.append(syn)
            sa = Ether() / IP(src=server_ip, dst=host) / TCP(sport=port, dport=sport, flags="SA")
            sa.time = syn.time + 0.03
            packets.append(sa)
            ack = Ether() / IP(src=host, dst=server_ip) / TCP(sport=sport, dport=port, flags="A")
            ack.time = sa.time + 0.01
            packets.append(ack)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated evasion IP rotation PCAP: {output_path} ({len(packets)} packets)")


def generate_evasion_jittery_beacon_pcap(output_path: Path) -> None:
    """Evasion test: DNS beaconing with high jitter to defeat periodicity detection.

    Beacon interval: 30s base with +-20s uniform jitter (CV > 1.0).
    50% of queries go to legitimate domains to dilute the signal.
    Tests periodicity detector's tolerance to noisy timing.
    """
    import random

    random.seed(51)
    packets = []
    base_ts = 1705312200.0

    beaconer_ip = "10.100.7.10"
    dns_server = "8.8.8.8"
    c2_domain = "cdn-assets.legit-service.com"
    normal_hosts = ["10.50.1.10", "10.50.1.11"]

    legit_domains = [
        "www.google.com", "mail.google.com", "cdn.jsdelivr.net",
        "api.github.com", "fonts.googleapis.com", "www.stackoverflow.com",
        "docs.python.org", "pypi.org", "www.npmjs.com", "registry.npmjs.org",
    ]

    # Jittery beaconing: 30 beacon queries with high timing variance
    current_time = base_ts
    for i in range(30):
        # Beacon query to C2
        pkt = Ether() / IP(src=beaconer_ip, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=c2_domain))
        pkt.time = current_time
        packets.append(pkt)

        # Intersperse legitimate query (50% of the time)
        if random.random() < 0.5:
            legit_domain = random.choice(legit_domains)
            legit_pkt = Ether() / IP(src=beaconer_ip, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=legit_domain))
            legit_pkt.time = current_time + random.uniform(1, 5)
            packets.append(legit_pkt)

        # High jitter: 30s base +- 20s uniform noise (range 10-50s)
        interval = 30 + random.uniform(-20, 20)
        current_time += max(5, interval)  # minimum 5s gap

    # Normal DNS from other hosts
    for host in normal_hosts:
        for i in range(20):
            domain = random.choice(legit_domains)
            pkt = Ether() / IP(src=host, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            pkt.time = base_ts + random.uniform(0, 1200)
            packets.append(pkt)

    # Normal TCP traffic
    web_servers = [("142.250.80.46", 443), ("140.82.121.4", 443)]
    for host in normal_hosts:
        for i in range(10):
            server_ip, port = web_servers[i % len(web_servers)]
            sport = RandShort()._fix()
            syn = Ether() / IP(src=host, dst=server_ip) / TCP(sport=sport, dport=port, flags="S")
            syn.time = base_ts + random.uniform(0, 1200)
            packets.append(syn)
            sa = Ether() / IP(src=server_ip, dst=host) / TCP(sport=port, dport=sport, flags="SA")
            sa.time = syn.time + 0.03
            packets.append(sa)
            ack = Ether() / IP(src=host, dst=server_ip) / TCP(sport=sport, dport=port, flags="A")
            ack.time = sa.time + 0.01
            packets.append(ack)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated evasion jittery beacon PCAP: {output_path} ({len(packets)} packets)")


def generate_evasion_slow_drip_pcap(output_path: Path) -> None:
    """Evasion test: extremely slow DNS exfiltration (1 query per 5 minutes).

    Only 12 queries over 1 hour to C2 domain. Heavy legitimate traffic
    interspersed to create poor signal-to-noise ratio.
    Tests whether the detector catches extremely slow beaconing.
    """
    import hashlib
    import random

    random.seed(52)
    packets = []
    base_ts = 1705312200.0

    exfiltrator_ip = "10.100.7.20"
    dns_server = "8.8.8.8"
    c2_domain = "telemetry.cloud-analytics.net"
    normal_hosts = [f"10.50.1.{i}" for i in range(10, 15)]

    legit_domains = [
        "www.google.com", "mail.google.com", "cdn.jsdelivr.net",
        "api.github.com", "www.stackoverflow.com", "docs.python.org",
    ]

    # Slow drip: 12 queries over 1 hour (every 5 minutes)
    for i in range(12):
        data_hash = hashlib.md5(f"slow_exfil_{i}".encode()).hexdigest()[:8]
        query = f"{data_hash}.{c2_domain}"
        pkt = Ether() / IP(src=exfiltrator_ip, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=query))
        pkt.time = base_ts + (i * 300) + random.uniform(0, 30)
        packets.append(pkt)

    # Also some legit DNS from the exfiltrator to blend in
    for i in range(15):
        domain = random.choice(legit_domains)
        pkt = Ether() / IP(src=exfiltrator_ip, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        pkt.time = base_ts + random.uniform(0, 3600)
        packets.append(pkt)

    # Heavy normal traffic from 5 hosts (overwhelm signal)
    web_servers = [("142.250.80.46", 443), ("140.82.121.4", 443), ("151.101.1.69", 80)]
    for host in normal_hosts:
        # DNS
        for i in range(30):
            domain = random.choice(legit_domains)
            pkt = Ether() / IP(src=host, dst=dns_server) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            pkt.time = base_ts + random.uniform(0, 3600)
            packets.append(pkt)
        # TCP with complete handshake
        for i in range(40):
            server_ip, port = web_servers[i % len(web_servers)]
            sport = RandShort()._fix()
            syn = Ether() / IP(src=host, dst=server_ip) / TCP(sport=sport, dport=port, flags="S")
            syn.time = base_ts + random.uniform(0, 3600)
            packets.append(syn)
            sa = Ether() / IP(src=server_ip, dst=host) / TCP(sport=port, dport=sport, flags="SA")
            sa.time = syn.time + 0.03
            packets.append(sa)
            ack = Ether() / IP(src=host, dst=server_ip) / TCP(sport=sport, dport=port, flags="A")
            ack.time = sa.time + 0.01
            packets.append(ack)

    wrpcap(str(output_path), packets)
    logger.info(f"Generated evasion slow drip PCAP: {output_path} ({len(packets)} packets)")


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    generate_scan_pcap(OUTPUT_DIR / "synthetic_scan.pcap")
    generate_beacon_pcap(OUTPUT_DIR / "synthetic_beacon.pcap")
    generate_benign_pcap(OUTPUT_DIR / "synthetic_benign.pcap")
    generate_mixed_pcap(OUTPUT_DIR / "synthetic_mixed.pcap")
    generate_dns_exfil_pcap(OUTPUT_DIR / "synthetic_dns_exfil.pcap")
    generate_multi_attacker_pcap(OUTPUT_DIR / "synthetic_multi_attacker.pcap")
    generate_killchain_pcap(OUTPUT_DIR / "synthetic_killchain.pcap")
    generate_slow_scan_pcap(OUTPUT_DIR / "synthetic_slow_scan.pcap")
    generate_noisy_benign_pcap(OUTPUT_DIR / "synthetic_noisy_benign.pcap")

    # Adversarial evasion PCAPs — designed to challenge detector thresholds
    generate_evasion_ip_rotation_pcap(OUTPUT_DIR / "synthetic_evasion_ip_rotation.pcap")
    generate_evasion_jittery_beacon_pcap(OUTPUT_DIR / "synthetic_evasion_jittery_beacon.pcap")
    generate_evasion_slow_drip_pcap(OUTPUT_DIR / "synthetic_evasion_slow_drip.pcap")

    logger.info(f"\nAll synthetic PCAPs generated in {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
