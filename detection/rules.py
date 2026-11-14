#!/usr/bin/env python3
"""SentinelAI Phase 2 - rule-based detection engine.

Feed every PacketInfo from the sniffer into Detector.process().
It returns a list of Alert objects (usually empty).

Thresholds and the allowlist come from config.json (see load_config).
Detector() with no argument uses the built-in DEFAULTS below.
"""
import copy
import ipaddress
import json
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from sniffer.sniffer import PacketInfo

# ---- Default thresholds ----------------------------------------------
DEFAULTS = {
    "port_scan":    {"ports": 20, "window": 5},     # distinct ports within window (s)
    "slow_scan":    {"ports": 20, "window": 60},    # catches slow scans
    "stealth_scan": {"ports": 10, "window": 30},    # FIN / NULL / Xmas probes
    "icmp_flood":   {"count": 50, "window": 5},     # echo requests within window
    "syn_flood":    {"count": 100, "window": 5},    # SYNs to one ip:port within window
    "brute_force":  {"count": 10, "window": 30,     # connections to one login port
                     "login_ports": [21, 22, 23, 3389, 3306, 5900]},
    "alert_cooldown": 30,                           # one alert per rule per source in this time
    "allowlist": [],                                # trusted IPs / networks, e.g. "192.168.1.10", "10.0.0.0/24"
}
# -----------------------------------------------------------------------


def load_config(path=None) -> dict:
    """Read config.json and fill anything missing from DEFAULTS.

    Raises ValueError with a readable message if the file is not valid.
    """
    cfg = copy.deepcopy(DEFAULTS)
    if path is None or not Path(path).exists():
        return cfg
    try:
        user = json.loads(Path(path).read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"{path} is not valid JSON: {e}")
    if not isinstance(user, dict):
        raise ValueError(f"{path} must contain a JSON object")
    for key, value in user.items():
        if key.startswith("_"):                       # "_comment" etc.
            continue
        if key not in cfg:
            raise ValueError(f"unknown setting '{key}' in {path}")
        if isinstance(cfg[key], dict):
            if not isinstance(value, dict):
                raise ValueError(f"'{key}' must be an object")
            for sub, v in value.items():
                if sub not in cfg[key]:
                    raise ValueError(f"unknown setting '{key}.{sub}' in {path}")
                cfg[key][sub] = v
        else:
            cfg[key] = value
    # basic sanity checks
    for key, section in cfg.items():
        if isinstance(section, dict):
            for sub, v in section.items():
                if sub == "login_ports":
                    if not all(isinstance(x, int) for x in v):
                        raise ValueError("'brute_force.login_ports' must be a list of numbers")
                elif not isinstance(v, (int, float)) or v <= 0:
                    raise ValueError(f"'{key}.{sub}' must be a number above 0")
    if not isinstance(cfg["alert_cooldown"], (int, float)) or cfg["alert_cooldown"] < 0:
        raise ValueError("'alert_cooldown' must be a number (0 or more)")
    if not isinstance(cfg["allowlist"], list):
        raise ValueError("'allowlist' must be a list")
    for entry in cfg["allowlist"]:
        try:
            ipaddress.ip_network(str(entry), strict=False)
        except ValueError:
            raise ValueError(f"allowlist entry '{entry}' is not an IP address or network")
    return cfg


@dataclass
class Alert:
    time: str
    rule: str
    severity: str
    src_ip: str
    dst_ip: str
    description: str

    def to_dict(self) -> dict:
        return asdict(self)


def _slide(dq: deque, now: float, window: float, key=lambda x: x) -> None:
    """Drop entries older than the window (oldest are on the left)."""
    while dq and key(dq[0]) < now - window:
        dq.popleft()


class Detector:
    def __init__(self, config: Optional[dict] = None):
        self.cfg = config if config is not None else copy.deepcopy(DEFAULTS)
        self.cooldown = self.cfg["alert_cooldown"]
        self.max_window = max(self.cfg[k]["window"] for k in
                              ("port_scan", "slow_scan", "stealth_scan",
                               "icmp_flood", "syn_flood", "brute_force"))
        self.trusted = [ipaddress.ip_network(str(e), strict=False)
                        for e in self.cfg["allowlist"]]
        self._trusted_cache: Dict[str, bool] = {}

        self.scan: Dict[str, deque] = defaultdict(deque)    # src -> (ts, dst_port)
        self.slow: Dict[str, deque] = defaultdict(deque)    # src -> (ts, dst_port)
        self.stealth: Dict[str, deque] = defaultdict(deque) # src -> (ts, dst_port, kind)
        self.icmp: Dict[str, deque] = defaultdict(deque)    # src -> ts
        self.syn: Dict[tuple, deque] = defaultdict(deque)   # (dst_ip, dst_port) -> ts
        self.brute: Dict[tuple, deque] = defaultdict(deque) # (src, dst_ip, dst_port) -> ts
        self.last_alert: Dict[tuple, float] = {}
        self.arp_table: Dict[str, str] = {}                 # ip -> MAC first seen
        self._seen = 0

    # ------------------------------------------------------------------
    def process(self, p: PacketInfo) -> List[Alert]:
        self._seen += 1
        if self._seen % 5000 == 0:
            self._cleanup(p.timestamp)

        found: List[Optional[Alert]] = []
        if p.protocol == "ARP":
            # never skipped: an attacker could claim a trusted address
            found.append(self._arp_spoof(p))
        elif self._is_trusted(p.src_ip):
            return []
        elif p.protocol == "TCP":
            if self._is_syn(p):
                found += [self._port_scan(p), self._slow_scan(p),
                          self._syn_flood(p), self._brute_force(p)]
            kind = self._stealth_kind(p)
            if kind:
                found.append(self._stealth_scan(p, kind))
        elif p.protocol == "ICMP" and p.icmp_type == 8:   # echo request
            found.append(self._icmp_flood(p))
        return [a for a in found if a]

    # ------------------------------------------------------------------
    def _is_trusted(self, ip: str) -> bool:
        if not self.trusted:
            return False
        hit = self._trusted_cache.get(ip)
        if hit is None:
            try:
                addr = ipaddress.ip_address(ip)
                hit = any(addr in net for net in self.trusted if net.version == addr.version)
            except ValueError:
                hit = False
            if len(self._trusted_cache) < 10000:
                self._trusted_cache[ip] = hit
        return hit

    @staticmethod
    def _is_syn(p: PacketInfo) -> bool:
        """New connection attempt: SYN set, ACK not set."""
        return bool(p.flags) and "S" in p.flags and "A" not in p.flags

    @staticmethod
    def _stealth_kind(p: PacketInfo) -> Optional[str]:
        """Name of an abnormal TCP flag pattern, or None for normal packets."""
        f = set(p.flags or "")
        if not f:
            return "NULL"                       # no flags at all
        if f == {"F"}:
            return "FIN"                        # FIN without ACK
        if {"F", "P", "U"} <= f:
            return "Xmas"                       # FIN + PSH + URG
        if "S" in f and ("F" in f or "R" in f):
            return "SYN+FIN/RST"                # impossible combination
        return None

    def _allowed(self, rule: str, key: str, now: float,
                 cooldown: Optional[float] = None) -> bool:
        """Rate limit: one alert per (rule, key) every `cooldown` seconds."""
        if cooldown is None:
            cooldown = self.cooldown
        k = (rule, key)
        if now - self.last_alert.get(k, -cooldown - 1) < cooldown:
            return False
        self.last_alert[k] = now
        return True

    @staticmethod
    def _alert(p: PacketInfo, rule: str, severity: str, text: str) -> Alert:
        return Alert(datetime.fromtimestamp(p.timestamp).isoformat(timespec="seconds"),
                     rule, severity, p.src_ip, p.dst_ip, text)

    # ---- rules -------------------------------------------------------
    def _port_scan(self, p: PacketInfo) -> Optional[Alert]:
        c = self.cfg["port_scan"]
        dq = self.scan[p.src_ip]
        dq.append((p.timestamp, p.dst_port))
        _slide(dq, p.timestamp, c["window"], key=lambda x: x[0])
        ports = {port for _, port in dq}
        if len(ports) >= c["ports"] and self._allowed("Port Scan", p.src_ip, p.timestamp):
            # a fast scan is already reported, so do not also report it as a slow one
            self.last_alert[("Slow Port Scan", p.src_ip)] = p.timestamp
            return self._alert(p, "Port Scan", "HIGH",
                               f"{len(ports)} distinct ports probed in {c['window']}s")
        return None

    def _slow_scan(self, p: PacketInfo) -> Optional[Alert]:
        c = self.cfg["slow_scan"]
        dq = self.slow[p.src_ip]
        dq.append((p.timestamp, p.dst_port))
        _slide(dq, p.timestamp, c["window"], key=lambda x: x[0])
        ports = {port for _, port in dq}
        if (len(ports) >= c["ports"] and
                self._allowed("Slow Port Scan", p.src_ip, p.timestamp, c["window"])):
            return self._alert(p, "Slow Port Scan", "MEDIUM",
                               f"{len(ports)} distinct ports probed in {c['window']}s (slow scan)")
        return None

    def _stealth_scan(self, p: PacketInfo, kind: str) -> Optional[Alert]:
        c = self.cfg["stealth_scan"]
        dq = self.stealth[p.src_ip]
        dq.append((p.timestamp, p.dst_port, kind))
        _slide(dq, p.timestamp, c["window"], key=lambda x: x[0])
        ports = {port for _, port, _ in dq}
        if len(ports) >= c["ports"] and self._allowed("Stealth Scan", p.src_ip, p.timestamp):
            top = Counter(k for _, _, k in dq).most_common(1)[0][0]
            return self._alert(p, "Stealth Scan", "HIGH",
                               f"{len(ports)} distinct ports probed with {top} packets "
                               f"in {c['window']}s")
        return None

    def _arp_spoof(self, p: PacketInfo) -> Optional[Alert]:
        """Alert when an IP address suddenly belongs to a different MAC address."""
        ip, mac = p.src_ip, (p.src_mac or "").lower()
        if not mac or ip in ("", "0.0.0.0"):      # 0.0.0.0 = address probe, ignore
            return None
        known = self.arp_table.get(ip)
        if known is None:
            if len(self.arp_table) < 10000:
                self.arp_table[ip] = mac
            return None
        if known == mac:
            return None
        self.arp_table[ip] = mac                  # remember the new owner
        if self._allowed("ARP Spoofing", ip, p.timestamp):
            return self._alert(p, "ARP Spoofing", "HIGH",
                               f"{ip} changed from MAC {known} to {mac} "
                               f"(possible man-in-the-middle)")
        return None

    def _icmp_flood(self, p: PacketInfo) -> Optional[Alert]:
        c = self.cfg["icmp_flood"]
        dq = self.icmp[p.src_ip]
        dq.append(p.timestamp)
        _slide(dq, p.timestamp, c["window"])
        if len(dq) >= c["count"] and self._allowed("ICMP Flood", p.src_ip, p.timestamp):
            return self._alert(p, "ICMP Flood", "MEDIUM",
                               f"{len(dq)} echo requests in {c['window']}s")
        return None

    def _syn_flood(self, p: PacketInfo) -> Optional[Alert]:
        c = self.cfg["syn_flood"]
        target = (p.dst_ip, p.dst_port)
        dq = self.syn[target]
        dq.append(p.timestamp)
        _slide(dq, p.timestamp, c["window"])
        if len(dq) >= c["count"] and self._allowed("SYN Flood", f"{target}", p.timestamp):
            return self._alert(p, "SYN Flood", "CRITICAL",
                               f"{len(dq)} SYN packets to {p.dst_ip}:{p.dst_port} in {c['window']}s")
        return None

    def _brute_force(self, p: PacketInfo) -> Optional[Alert]:
        c = self.cfg["brute_force"]
        if p.dst_port not in c["login_ports"]:
            return None
        key = (p.src_ip, p.dst_ip, p.dst_port)
        dq = self.brute[key]
        dq.append(p.timestamp)
        _slide(dq, p.timestamp, c["window"])
        if len(dq) >= c["count"] and self._allowed("Brute Force Attempt", f"{key}", p.timestamp):
            return self._alert(p, "Brute Force Attempt", "HIGH",
                               f"{len(dq)} connections to login port {p.dst_port} in {c['window']}s")
        return None

    # ------------------------------------------------------------------
    def _cleanup(self, now: float) -> None:
        """Forget sources that have been quiet, so memory stays small."""
        cutoff = now - self.max_window
        tables = (
            (self.scan, lambda e: e[0]),   # entries are (timestamp, port)
            (self.slow, lambda e: e[0]),
            (self.stealth, lambda e: e[0]),
            (self.icmp, lambda e: e),      # entries are timestamps
            (self.syn, lambda e: e),
            (self.brute, lambda e: e),
        )
        for table, ts_of in tables:
            for k in list(table):
                dq = table[k]
                if not dq or ts_of(dq[-1]) < cutoff:
                    del table[k]
        for k in list(self.last_alert):
            if self.last_alert[k] < now - self.max_window:
                del self.last_alert[k]