#!/usr/bin/env python3
"""Triage the alerts saved by the IDS.

Usage (from the project root, no root needed):
    ./venv/bin/python -m triage.run                  # every alert not triaged yet
    ./venv/bin/python -m triage.run --offline        # never call the API
    ./venv/bin/python -m triage.run --limit 5        # only the 5 newest
"""
import argparse
import json
import sys
from pathlib import Path

from triage.agent import ROOT, TriageAgent, format_card, save_result

ALERTS = ROOT / "logs" / "alerts.json"
RESULTS = ROOT / "logs" / "triage.json"


def read_lines(path: Path) -> list:
    rows = []
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def key(alert: dict) -> str:
    return json.dumps(alert, sort_keys=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="AI triage for SentinelAI alerts")
    ap.add_argument("--alerts", default=str(ALERTS), help="alert log written by the IDS")
    ap.add_argument("--out", default=str(RESULTS), help="where triage results are saved")
    ap.add_argument("--offline", action="store_true", help="use built-in explanations only")
    ap.add_argument("--limit", type=int, help="only triage the newest N alerts")
    a = ap.parse_args(argv)

    alerts_path, out_path = Path(a.alerts), Path(a.out)
    if not alerts_path.exists():
        sys.exit(f"[!] No alert log at {alerts_path}. Run the IDS first.")
    done = {key(r.get("alert", {})) for r in read_lines(out_path)}
    todo = [x for x in read_lines(alerts_path) if isinstance(x, dict) and key(x) not in done]
    if a.limit:
        todo = todo[-a.limit:]
    if not todo:
        print("[*] Nothing new to triage.")
        return 0

    agent = TriageAgent.from_env(force_offline=a.offline)
    print(f"[*] Triage mode: {agent.mode}. {len(todo)} alert(s) to triage.\n")
    for alert in todo:
        t = agent.triage(alert)
        print(format_card(alert, t) + "\n")
        save_result(out_path, alert, t)
    s = agent.stats
    print(f"[*] Done. API answers: {s['api']}, offline: {s['offline']}, cached: {s['cached']}. "
          f"Saved to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())