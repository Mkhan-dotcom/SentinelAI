"""Unit tests for the detection rules.

No root, no network and no real traffic needed: each test feeds made-up
packets to the Detector and checks which alerts come out.

Run from the project root:   ./venv/bin/python -m pytest -q
"""
import tempfile

import pytest

from detection.rules import DEFAULTS, Detector, load_config
from sniffer.sniffer import PacketInfo

ME = "10.0.0.9"        # the "attacker" in most tests
TARGET = "10.0.0.1"


def tcp(t, dport, flags="S", src=ME, dst=TARGET, sport=40000):
    return PacketInfo(t, "TCP", src, dst, sport, dport, 60, flags, None)


def icmp(t, icmp_type=8, src=ME):
    return PacketInfo(t, "ICMP", src, TARGET, None, None, 98, None, icmp_type)


def arp(t, ip, mac):
    return PacketInfo(t, "ARP", ip, TARGET, None, None, 42, "op=2", None, mac)


def alerts(packets, config=None):
    det = Detector(config)
    out = []
    for p in packets:
        out += det.process(p)
    return out


def rules(packets, config=None):
    return [a.rule for a in alerts(packets, config)]


def custom(**changes):
    cfg = load_config(None)
    for key, value in changes.items():
        if isinstance(value, dict):
            cfg[key].update(value)
        else:
            cfg[key] = value
    return cfg


# ---------------------------------------------------------------- port scans
def test_fast_port_scan_is_detected():
    assert rules([tcp(100 + i * 0.01, i + 1) for i in range(30)]) == ["Port Scan"]


def test_scan_just_below_the_limit_is_ignored():
    assert rules([tcp(100 + i * 0.01, i + 1) for i in range(19)]) == []


def test_same_port_repeated_is_not_a_scan():
    assert "Port Scan" not in rules([tcp(100 + i * 0.01, 443) for i in range(200)])


def test_slow_scan_is_detected():
    assert rules([tcp(100 + i * 0.42, i + 1) for i in range(100)]) == ["Slow Port Scan"]


def test_scan_slower_than_the_window_is_ignored():
    assert rules([tcp(100 + i * 6, i + 1) for i in range(20)]) == []


def test_fast_scan_is_not_reported_twice():
    assert rules([tcp(100 + i * 0.005, i + 1) for i in range(200)]) == ["Port Scan"]


def test_port_scan_does_not_look_like_a_syn_flood():
    assert "SYN Flood" not in rules([tcp(100 + i * 0.005, i + 1) for i in range(300)])


# ------------------------------------------------------------- stealth scans
def test_fin_null_and_xmas_scans_are_detected():
    for flags, name in (("F", "FIN"), ("", "NULL"), ("FPU", "Xmas")):
        found = alerts([tcp(100 + i * 0.01, i + 1, flags) for i in range(30)])
        assert [a.rule for a in found] == ["Stealth Scan"]
        assert name in found[0].description


def test_few_stealth_probes_are_ignored():
    assert rules([tcp(100 + i * 0.01, i + 1, "F") for i in range(9)]) == []


def test_normal_connection_closing_is_not_a_stealth_scan():
    assert rules([tcp(100 + i * 0.01, 1000 + i, "FA") for i in range(200)]) == []


def test_ordinary_tcp_traffic_raises_nothing():
    packets = [tcp(100 + i * 0.01, 443, flags) for i in range(50) for flags in ("PA", "A", "SA", "RA")]
    assert rules(packets) == []


def test_syn_ack_replies_are_not_new_connections():
    # a busy server answering many clients must not look like a scanner
    replies = [tcp(100 + i * 0.01, 40000 + i, "SA", src=TARGET, dst=ME) for i in range(300)]
    assert rules(replies) == []


# ------------------------------------------------------------------- floods
def test_syn_flood_is_detected_and_critical():
    packets = [tcp(100 + i * 0.005, 80, src=f"10.1.0.{i % 200}", sport=1000 + i) for i in range(150)]
    found = alerts(packets)
    assert [a.rule for a in found] == ["SYN Flood"]
    assert found[0].severity == "CRITICAL"


def test_icmp_flood_is_detected():
    assert rules([icmp(100 + i * 0.01) for i in range(60)]) == ["ICMP Flood"]


def test_icmp_just_below_the_limit_is_ignored():
    assert rules([icmp(100 + i * 0.01) for i in range(49)]) == []


def test_echo_replies_are_not_counted():
    assert rules([icmp(100 + i * 0.01, icmp_type=0) for i in range(500)]) == []


# -------------------------------------------------------------- brute force
def test_brute_force_on_ssh_port_is_detected():
    assert rules([tcp(100 + i * 0.2, 22, sport=5000 + i) for i in range(10)]) == ["Brute Force Attempt"]


def test_brute_force_just_below_the_limit_is_ignored():
    assert rules([tcp(100 + i * 0.2, 22, sport=5000 + i) for i in range(9)]) == []


def test_many_connections_to_a_normal_port_are_not_brute_force():
    assert rules([tcp(100 + i * 0.2, 8080, sport=5000 + i) for i in range(50)]) == []


# ------------------------------------------------------------- arp spoofing
GATEWAY = "52:55:0a:00:02:02"
FORGED = "aa:bb:cc:dd:ee:ff"


def test_arp_spoofing_is_detected():
    found = alerts([arp(1, "10.0.2.2", GATEWAY), arp(5, "10.0.2.2", FORGED)])
    assert [a.rule for a in found] == ["ARP Spoofing"]
    assert GATEWAY in found[0].description and FORGED in found[0].description


def test_same_mac_repeated_is_quiet():
    assert rules([arp(i, "10.0.2.2", GATEWAY) for i in range(50)]) == []


def test_mac_case_does_not_matter():
    assert rules([arp(1, "10.0.2.2", GATEWAY.upper()), arp(2, "10.0.2.2", GATEWAY)]) == []


def test_address_probes_are_ignored():
    assert rules([arp(1, "0.0.0.0", "11:22:33:44:55:66"), arp(2, "0.0.0.0", "77:88:99:aa:bb:cc")]) == []


def test_many_different_hosts_are_quiet():
    assert rules([arp(1, f"10.0.2.{i}", f"02:00:00:00:00:{i:02x}") for i in range(2, 60)]) == []


def test_arp_flip_flopping_is_rate_limited():
    packets = [arp(1, "10.0.2.2", GATEWAY), arp(2, "10.0.2.2", FORGED),
               arp(3, "10.0.2.2", GATEWAY), arp(4, "10.0.2.2", FORGED)]
    assert rules(packets) == ["ARP Spoofing"]


# ----------------------------------------------------------------- cooldown
def test_alert_cooldown():
    def burst(start):
        return [tcp(start + i * 0.01, i + 1) for i in range(30)]
    assert rules(burst(100) + burst(110)) == ["Port Scan"]                 # 10 s later: suppressed
    assert rules(burst(100) + burst(140)) == ["Port Scan", "Port Scan"]    # 40 s later: reported again


def test_old_sources_are_forgotten():
    det = Detector()
    for i in range(4999):
        det.process(tcp(100, i + 1))
    assert ME in det.scan
    det.process(tcp(1000, 80, src="10.0.0.77"))          # 5000th packet triggers the cleanup
    assert ME not in det.scan


# ---------------------------------------------------------------- allowlist
def test_allowlisted_address_is_skipped():
    scan = [tcp(100 + i * 0.01, i + 1) for i in range(30)]
    assert rules(scan, custom(allowlist=[ME])) == []


def test_allowlisted_network_is_skipped():
    scan = [tcp(100 + i * 0.01, i + 1) for i in range(30)]
    assert rules(scan, custom(allowlist=["10.0.0.0/24"])) == []


def test_other_sources_are_still_checked():
    scan = [tcp(100 + i * 0.01, i + 1, src="10.0.0.50") for i in range(30)]
    assert rules(scan, custom(allowlist=[ME])) == ["Port Scan"]


def test_allowlist_never_skips_arp():
    packets = [arp(1, ME, "aa:aa:aa:aa:aa:aa"), arp(2, ME, "bb:bb:bb:bb:bb:bb")]
    assert rules(packets, custom(allowlist=[ME])) == ["ARP Spoofing"]


# ------------------------------------------------------------ configuration
def test_custom_threshold_is_used():
    scan = [tcp(100 + i * 0.01, i + 1) for i in range(8)]
    assert rules(scan) == []
    assert rules(scan, custom(port_scan={"ports": 5})) == ["Port Scan"]


def test_custom_login_port_is_used():
    packets = [tcp(100 + i * 0.1, 8022, sport=5000 + i) for i in range(6)]
    cfg = custom(brute_force={"count": 5, "login_ports": [22, 8022]})
    assert rules(packets, cfg) == ["Brute Force Attempt"]


def _config_file(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    f.write(text)
    f.close()
    return f.name


def test_missing_config_file_gives_defaults():
    assert load_config("/no/such/file.json") == DEFAULTS


def test_partial_config_keeps_the_other_defaults():
    path = _config_file('{"port_scan": {"ports": 30}, "_comment": "hello"}')
    cfg = load_config(path)
    assert cfg["port_scan"] == {"ports": 30, "window": 5}
    assert cfg["icmp_flood"] == DEFAULTS["icmp_flood"]


def test_bad_config_files_are_rejected():
    bad = [
        '{"port_scan": ',                                  # not JSON
        '[1, 2]',                                          # not an object
        '{"portscan": {"ports": 5}}',                      # unknown setting
        '{"port_scan": {"port": 5}}',                      # unknown sub-setting
        '{"icmp_flood": {"count": -1}}',                   # negative number
        '{"icmp_flood": {"count": "many"}}',               # not a number
        '{"allowlist": ["not-an-ip"]}',                    # bad address
        '{"allowlist": "10.0.0.1"}',                       # should be a list
        '{"brute_force": {"login_ports": ["ssh"]}}',       # ports must be numbers
        '{"alert_cooldown": -5}',                          # negative cooldown
    ]
    for text in bad:
        with pytest.raises(ValueError):
            load_config(_config_file(text))


def test_shipped_config_json_matches_the_defaults():
    from pathlib import Path
    shipped = Path(__file__).resolve().parent.parent / "config.json"
    if shipped.exists():
        assert load_config(shipped) == DEFAULTS