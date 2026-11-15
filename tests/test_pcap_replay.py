"""Replays a fixed capture file through the whole pipeline (file reading,
packet parsing and every rule) and checks the exact alerts.

Run from the project root:   ./venv/bin/python -m pytest -q
"""
from detection.replay import analyse
from detection.rules import load_config
from tests.sample_traffic import ATTACKER, EXPECTED_ALERTS, write_pcap


def test_capture_gives_exactly_the_expected_alerts(tmp_path):
    pcap = tmp_path / "sample.pcap"
    written = write_pcap(pcap)
    count, alerts, _ = analyse(pcap)
    assert count == written
    assert [a.rule for a in alerts] == EXPECTED_ALERTS


def test_normal_web_dns_and_ping_traffic_is_not_flagged(tmp_path):
    pcap = tmp_path / "sample.pcap"
    write_pcap(pcap)
    # Allowlist every attacking address. What is left is the normal traffic
    # (which must stay silent) plus the ARP attack, which is never skipped.
    cfg = load_config(None)
    cfg["allowlist"] = [ATTACKER, "172.16.0.0/24"]
    _, alerts, _ = analyse(pcap, cfg)
    assert [a.rule for a in alerts] == ["ARP Spoofing"]


def test_allowlisting_the_attacker_leaves_only_other_sources(tmp_path):
    pcap = tmp_path / "sample.pcap"
    write_pcap(pcap)
    cfg = load_config(None)
    cfg["allowlist"] = [ATTACKER]
    _, alerts, _ = analyse(pcap, cfg)
    assert [a.rule for a in alerts] == ["SYN Flood", "ARP Spoofing"]