#!/usr/bin/env python3
"""SentinelAI Phase 4 - repeatable detection test suite.

Runs each attack N times against your own VM (loopback) and counts how often
the right alert fires (detection rate). Then runs harmless activity N times
and counts wrong alerts (false positives).

Each trial uses a fresh Detector, so the 30 s alert cooldown never hides a
result. Nothing is written to logs/alerts.json.

Run from the project root, with sudo:
    sudo ./venv/bin/python -m tests.run_tests -n 5
    sudo ./venv/bin/python -m tests.run_tests -n 20     # numbers for the CV
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from scapy.all import AsyncSniffer

from sniffer.sniffer import DuplicateFilter, open_capture_socket, parse_packet
from detection.rules import Detector

OUT_DIR = Path(__file__).resolve().parent.parent / "report" / "output"

# (name, alert that must fire, command, tools needed)
ATTACKS = [
    ("Port Scan", "Port Scan",
     ["nmap", "-sS", "-p", "1-200", "127.0.0.1"], ["nmap"]),
    ("Slow Port Scan", "Slow Port Scan",
     ["nmap", "-sS", "-T2", "-p", "1-100", "127.0.0.1"], ["nmap"]),
    ("FIN Scan (stealth)", "Stealth Scan",
     ["nmap", "-sF", "-p", "1-100", "127.0.0.1"], ["nmap"]),
    ("NULL Scan (stealth)", "Stealth Scan",
     ["nmap", "-sN", "-p", "1-100", "127.0.0.1"], ["nmap"]),
    ("Xmas Scan (stealth)", "Stealth Scan",
     ["nmap", "-sX", "-p", "1-100", "127.0.0.1"], ["nmap"]),
    ("ICMP Flood", "ICMP Flood",
     ["ping", "-f", "-c", "300", "127.0.0.1"], ["ping"]),
    ("Brute Force (SSH port)", "Brute Force Attempt",
     ["bash", "-c", "for i in $(seq 15); do nc -zw1 127.0.0.1 22; done"], ["bash", "nc"]),
    ("SYN Flood", "SYN Flood",
     ["hping3", "-S", "-p", "8080", "-c", "300", "-i", "u1000", "127.0.0.1"], ["hping3"]),
]

# (name, command, tools needed) - nothing here should raise an alert
BENIGN = [
    ("Idle (5 s, no activity)", ["sleep", "5"], ["sleep"]),
    ("Normal ping (5 packets)", ["ping", "-c", "5", "127.0.0.1"], ["ping"]),
    ("3 SSH-port connections", ["bash", "-c", "for i in 1 2 3; do nc -zw1 127.0.0.1 22; done"],
     ["bash", "nc"]),
    ("Single port check", ["nmap", "-p", "22", "127.0.0.1"], ["nmap"]),
    # just below each threshold: these must stay quiet
    ("Quick scan of 15 ports (below limit)", ["nmap", "-sS", "-p", "1-15", "127.0.0.1"], ["nmap"]),
    ("8 SSH-port connections (below limit)",
     ["bash", "-c", "for i in $(seq 8); do nc -zw1 127.0.0.1 22; done"], ["bash", "nc"]),
    ("40 pings in 4 s (below limit)", ["ping", "-c", "40", "-i", "0.1", "127.0.0.1"], ["ping"]),
]


def missing(tools):
    return [t for t in tools if shutil.which(t) is None]


def run_trial(cmd, iface):
    """Run one command while sniffing. Returns ([(rule, time)], start_time)."""
    detector = Detector()
    dedup = DuplicateFilter() if iface == "lo" else None   # lo shows every packet twice
    alerts = []

    def handle(pkt):
        if dedup and dedup.is_duplicate(pkt):
            return
        info = parse_packet(pkt)
        if info is None:
            return
        for a in detector.process(info):
            alerts.append((a.rule, time.time()))

    sock = open_capture_socket(iface)          # large buffer: no dropped packets
    sniffer = AsyncSniffer(opened_socket=sock, prn=handle, store=False)
    sniffer.start()
    time.sleep(1.5)                      # let the capture socket open
    t0 = time.time()
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(2)                        # let the last packets be analysed
    try:
        sniffer.stop()
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass
    time.sleep(1)
    return alerts, t0


def run_suite(n, iface):
    results = {"trials_per_test": n, "interface": iface, "attacks": [], "benign": []}

    print(f"\n=== Attack tests ({n} trials each) ===")
    for name, expected, cmd, tools in ATTACKS:
        gone = missing(tools)
        if gone:
            print(f"- {name}: SKIPPED (install {', '.join(gone)})")
            results["attacks"].append({"name": name, "skipped": True, "missing": gone})
            continue
        hits, latencies, extras = 0, [], set()
        for i in range(1, n + 1):
            alerts, t0 = run_trial(cmd, iface)
            got = [t for rule, t in alerts if rule == expected]
            extras |= {rule for rule, _ in alerts if rule != expected}
            if got:
                hits += 1
                latencies.append(min(got) - t0)
            print(f"  {name} trial {i}/{n}: {'DETECTED' if got else 'MISSED'}")
        results["attacks"].append({
            "name": name, "expected_alert": expected, "trials": n, "detected": hits,
            "detection_rate_pct": round(100 * hits / n, 1),
            "avg_latency_s": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "other_alerts_seen": sorted(extras),
        })

    print(f"\n=== Normal activity tests ({n} trials each) ===")
    for name, cmd, tools in BENIGN:
        gone = missing(tools)
        if gone:
            print(f"- {name}: SKIPPED (install {', '.join(gone)})")
            results["benign"].append({"name": name, "skipped": True, "missing": gone})
            continue
        false_alarms, seen = 0, set()
        for i in range(1, n + 1):
            alerts, _ = run_trial(cmd, iface)
            if alerts:
                false_alarms += 1
                seen |= {rule for rule, _ in alerts}
            print(f"  {name} trial {i}/{n}: {'FALSE ALARM' if alerts else 'clean'}")
        results["benign"].append({
            "name": name, "trials": n, "false_alarms": false_alarms,
            "false_alarm_rate_pct": round(100 * false_alarms / n, 1),
            "alerts_seen": sorted(seen),
        })
    return results


def totals(results):
    ran = [a for a in results["attacks"] if not a.get("skipped")]
    ben = [b for b in results["benign"] if not b.get("skipped")]
    t_att, t_hit = sum(a["trials"] for a in ran), sum(a["detected"] for a in ran)
    t_ben, t_fp = sum(b["trials"] for b in ben), sum(b["false_alarms"] for b in ben)
    return {
        "attack_trials": t_att, "attacks_detected": t_hit,
        "overall_detection_rate_pct": round(100 * t_hit / t_att, 1) if t_att else None,
        "benign_trials": t_ben, "false_alarms": t_fp,
        "overall_false_alarm_rate_pct": round(100 * t_fp / t_ben, 1) if t_ben else None,
    }


def markdown(results, tot):
    lines = ["| Attack | Trials | Detected | Detection rate | Avg time to alert |",
             "|---|---|---|---|---|"]
    for a in results["attacks"]:
        if a.get("skipped"):
            lines.append(f"| {a['name']} | - | - | skipped | - |")
        else:
            lat = f"{a['avg_latency_s']} s" if a["avg_latency_s"] is not None else "-"
            lines.append(f"| {a['name']} | {a['trials']} | {a['detected']} | "
                         f"{a['detection_rate_pct']}% | {lat} |")
    lines += ["", "| Normal activity | Trials | False alarms |", "|---|---|---|"]
    for b in results["benign"]:
        if b.get("skipped"):
            lines.append(f"| {b['name']} | - | skipped |")
        else:
            lines.append(f"| {b['name']} | {b['trials']} | {b['false_alarms']} |")
    lines += ["", f"**Overall:** {tot['attacks_detected']}/{tot['attack_trials']} attacks detected "
              f"({tot['overall_detection_rate_pct']}%), {tot['false_alarms']}/{tot['benign_trials']} "
              f"normal-activity trials raised a false alarm ({tot['overall_false_alarm_rate_pct']}%)."]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="SentinelAI detection test suite")
    ap.add_argument("-n", "--trials", type=int, default=5, help="trials per test (default 5)")
    ap.add_argument("-i", "--iface", default="lo", help="interface (default lo)")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[!] Run with: sudo ./venv/bin/python -m tests.run_tests")

    print("[*] SentinelAI test suite. Tests only touch 127.0.0.1 (your own VM).")
    try:
        results = run_suite(a.trials, a.iface)
    except KeyboardInterrupt:
        sys.exit("\n[*] Stopped.")

    tot = totals(results)
    results["totals"] = tot
    table = markdown(results, tot)
    print("\n" + table)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "test_results.json").write_text(json.dumps(results, indent=2))
    (OUT_DIR / "test_results.md").write_text(table + "\n")
    print("\n[*] Saved report/output/test_results.json and test_results.md")


if __name__ == "__main__":
    main()