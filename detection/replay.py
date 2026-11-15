#!/usr/bin/env python3
"""Analyse a saved capture file (.pcap) offline with the SentinelAI rules.

Usage (no root needed):
    ./venv/bin/python -m detection.replay capture.pcap
    ./venv/bin/python -m detection.replay capture.pcap --config config.json --log alerts_from_capture.json
"""
import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from scapy.all import PcapReader

from sniffer.sniffer import parse_packet
from detection.rules import Detector, load_config


def analyse(path, config=None):
    """Run every packet of a capture through the detector.

    Returns (packet_count, alerts, seconds_taken).
    """
    detector = Detector(config)
    alerts, count = [], 0
    reader = PcapReader(str(path))
    start = time.perf_counter()
    try:
        for pkt in reader:
            count += 1
            info = parse_packet(pkt)
            if info is not None:
                alerts += detector.process(info)
    finally:
        reader.close()
    return count, alerts, time.perf_counter() - start


def main():
    ap = argparse.ArgumentParser(description="Analyse a .pcap file with SentinelAI")
    ap.add_argument("pcap", help="capture file, e.g. from tcpdump or Wireshark")
    ap.add_argument("-c", "--config", help="settings file (default: built-in defaults)")
    ap.add_argument("--log", help="also save the alerts to this file (one JSON per line)")
    a = ap.parse_args()

    if not Path(a.pcap).exists():
        sys.exit(f"[!] File not found: {a.pcap}")
    try:
        cfg = load_config(a.config)
    except ValueError as e:
        sys.exit(f"[!] Config error: {e}")

    count, alerts, seconds = analyse(a.pcap, cfg)
    for al in alerts:
        print(f"[ALERT] {al.time}  {al.severity:<8} {al.rule:<20} "
              f"{al.src_ip} -> {al.dst_ip} | {al.description}")
    if a.log:
        with open(a.log, "w") as f:
            for al in alerts:
                f.write(json.dumps(al.to_dict()) + "\n")
        print(f"[*] Alerts saved to {a.log}")

    rate = count / seconds if seconds > 0 else 0
    print(f"\n[*] {count} packets analysed in {seconds:.2f}s ({rate:,.0f} packets/s), "
          f"{len(alerts)} alerts")
    for rule, n in Counter(al.rule for al in alerts).items():
        print(f"    {rule}: {n}")


if __name__ == "__main__":
    main()