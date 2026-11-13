#!/usr/bin/env python3
"""SentinelAI Phase 2 - run the sniffer and the rule-based detector together.

Usage (from the project root):
    sudo ./venv/bin/python -m detection.ids -i lo
"""
import argparse
import json
import time
from collections import Counter
from pathlib import Path

from sniffer.sniffer import start_sniffing
from detection.rules import Detector

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "alerts.json"

COLORS = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
RESET = "\033[0m"


def main():
    ap = argparse.ArgumentParser(description="SentinelAI rule-based IDS")
    ap.add_argument("-i", "--iface", help="interface, e.g. lo or enp0s3")
    ap.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp"')
    ap.add_argument("-v", "--verbose", action="store_true", help="print every packet")
    a = ap.parse_args()

    LOG_PATH.parent.mkdir(exist_ok=True)
    detector = Detector()
    counts = Counter()
    packets = 0

    def on_packet(info):
        nonlocal packets
        packets += 1
        for alert in detector.process(info):
            counts[alert.rule] += 1
            color = COLORS.get(alert.severity, "")
            print(f"{color}[ALERT] {alert.severity:<8} {alert.rule:<20}{RESET} "
                  f"{alert.src_ip} -> {alert.dst_ip} | {alert.description}")
            with open(LOG_PATH, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")

    print(f"[*] SentinelAI IDS started {time.strftime('%H:%M:%S')} "
          f"(iface={a.iface or 'default'}, filter={a.filter or 'none'})")
    print(f"[*] Alerts are saved to {LOG_PATH}\n[*] Ctrl+C to stop\n")
    try:
        start_sniffing(a.iface, a.filter, 0, on_packet=on_packet, verbose=a.verbose)
    except PermissionError:
        print("[!] Run with sudo ./venv/bin/python -m detection.ids ...")
    except KeyboardInterrupt:
        pass
    print(f"\n[*] Stopped. {packets} packets analysed, {sum(counts.values())} alerts.")
    for rule, n in counts.items():
        print(f"    {rule}: {n}")


if __name__ == "__main__":
    main()