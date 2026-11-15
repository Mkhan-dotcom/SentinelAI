#!/usr/bin/env python3
"""SentinelAI Phase 2 - run the sniffer and the rule-based detector together.

Usage (from the project root):
    sudo ./venv/bin/python -m detection.ids -i lo
    sudo ./venv/bin/python -m detection.ids -i enp0s3 --config config.json
    sudo ./venv/bin/python -m detection.ids -i lo --triage           # AI triage of each alert
    sudo ./venv/bin/python -m detection.ids -i lo --triage --no-api  # built-in explanations only
"""
import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

from sniffer.sniffer import start_sniffing
from detection.rules import Detector, load_config

ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = ROOT / "logs" / "alerts.json"
TRIAGE_PATH = ROOT / "logs" / "triage.json"
CONFIG_PATH = ROOT / "config.json"

COLORS = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
RESET = "\033[0m"


def main():
    ap = argparse.ArgumentParser(description="SentinelAI rule-based IDS")
    ap.add_argument("-i", "--iface", help="interface, e.g. lo or enp0s3")
    ap.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp"')
    ap.add_argument("-c", "--config", default=str(CONFIG_PATH),
                    help="settings file (default: config.json in the project folder)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every packet")
    ap.add_argument("--triage", action="store_true",
                    help="explain and prioritise each alert (AI agent, runs in the background)")
    ap.add_argument("--no-api", action="store_true",
                    help="with --triage: never call the API, use built-in explanations")
    a = ap.parse_args()

    try:
        cfg = load_config(a.config)
    except ValueError as e:
        sys.exit(f"[!] Config error: {e}")

    worker = None
    if a.triage:
        from triage.agent import TriageAgent, TriageWorker      # only loaded when asked for
        agent = TriageAgent.from_env(force_offline=a.no_api)
        worker = TriageWorker(agent, TRIAGE_PATH)

    LOG_PATH.parent.mkdir(exist_ok=True)
    detector = Detector(cfg)
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
            if worker:
                worker.submit(alert.to_dict())          # never blocks packet capture

    print(f"[*] SentinelAI IDS started {time.strftime('%H:%M:%S')} "
          f"(iface={a.iface or 'default'}, filter={a.filter or 'none'})")
    if Path(a.config).exists():
        print(f"[*] Settings loaded from {a.config}")
    else:
        print("[*] No config.json found, using default settings")
    if cfg["allowlist"]:
        print(f"[*] Allowlist active: {', '.join(map(str, cfg['allowlist']))} "
              f"(traffic from these sources is not checked, except ARP)")
    if worker:
        print(f"[*] AI triage on. Mode: {agent.mode}. Results: {TRIAGE_PATH}")
        worker.start()
    print(f"[*] Alerts are saved to {LOG_PATH}\n[*] Ctrl+C to stop\n")
    try:
        start_sniffing(a.iface, a.filter, 0, on_packet=on_packet, verbose=a.verbose)
    except PermissionError:
        print("[!] Run with sudo ./venv/bin/python -m detection.ids ...")
    except KeyboardInterrupt:
        pass
    if worker:
        print("\n[*] Finishing triage of the last alerts...")
        worker.finish(timeout=30)
        if worker.dropped:
            print(f"[!] {worker.dropped} alert(s) were not triaged because the queue was full "
                  f"(they are still in {LOG_PATH})")
    print(f"\n[*] Stopped. {packets} packets analysed, {sum(counts.values())} alerts.")
    for rule, n in counts.items():
        print(f"    {rule}: {n}")


if __name__ == "__main__":
    main()