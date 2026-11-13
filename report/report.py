#!/usr/bin/env python3
"""SentinelAI Phase 3 - intrusion report generator.

Reads logs/alerts.json (one JSON alert per line) and prints a SOC-style
summary. Also saves the summary as JSON and the alerts as CSV.

Usage (from the project root):
    python -m report.report                 # today's alerts
    python -m report.report --date 2026-11-13
    python -m report.report --all           # every alert in the log
"""
import argparse
import csv
import json
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = ROOT / "logs" / "alerts.json"
OUT_DIR = ROOT / "report" / "output"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
FIELDS = ["time", "rule", "severity", "src_ip", "dst_ip", "description"]


def load_alerts(path: Path) -> list:
    alerts, bad = [], 0
    if not path.exists():
        return alerts
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    if bad:
        print(f"[!] Skipped {bad} unreadable line(s) in {path.name}")
    return alerts


def summarize(alerts: list, label: str) -> dict:
    by_sev = Counter(a.get("severity", "UNKNOWN") for a in alerts)
    times = sorted(a["time"] for a in alerts if "time" in a)
    return {
        "report_for": label,
        "total_alerts": len(alerts),
        "by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
        "by_rule": dict(Counter(a.get("rule", "?") for a in alerts).most_common()),
        "top_sources": dict(Counter(a.get("src_ip", "?") for a in alerts).most_common(5)),
        "first_alert": times[0] if times else None,
        "last_alert": times[-1] if times else None,
    }


def print_summary(s: dict) -> None:
    print("=" * 52)
    print(f" SentinelAI Intrusion Report - {s['report_for']}")
    print("=" * 52)
    print(f" Total alerts : {s['total_alerts']}")
    if s["total_alerts"] == 0:
        print(" No alerts recorded. Nothing to report.")
        return
    print(f" First / last : {s['first_alert']}  ->  {s['last_alert']}")
    print("\n By severity")
    for sev, n in s["by_severity"].items():
        print(f"   {sev:<9} {n}")
    print("\n By rule")
    for rule, n in s["by_rule"].items():
        print(f"   {rule:<22} {n}")
    print("\n Top source IPs")
    for ip, n in s["top_sources"].items():
        print(f"   {ip:<18} {n}")


def save(summary: dict, alerts: list, label: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    jpath = OUT_DIR / f"report_{label}.json"
    cpath = OUT_DIR / f"alerts_{label}.csv"
    with open(jpath, "w") as f:
        json.dump(summary, f, indent=2)
    with open(cpath, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(alerts)
    print(f"\n[*] Saved {jpath.relative_to(ROOT)} and {cpath.relative_to(ROOT)}")


def main():
    ap = argparse.ArgumentParser(description="SentinelAI intrusion report")
    ap.add_argument("--date", help="YYYY-MM-DD (default: today)")
    ap.add_argument("--all", action="store_true", help="include every alert")
    a = ap.parse_args()

    alerts = load_alerts(LOG_PATH)
    if a.all:
        label = "all"
    else:
        label = a.date or date.today().isoformat()
        alerts = [x for x in alerts if str(x.get("time", "")).startswith(label)]

    summary = summarize(alerts, label)
    print_summary(summary)
    if alerts:
        save(summary, alerts, label)


if __name__ == "__main__":
    main()