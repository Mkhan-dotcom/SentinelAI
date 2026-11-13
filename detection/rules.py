#!/usr/bin/env python3
"""SentinelAI Phase 2 - rule-based detection engine.

Feed every PacketInfo from the sniffer into Detector.process().
It returns a list of Alert objects (usually empty).
"""
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional

from sniffer.sniffer import PacketInfo

# ---- Thresholds (tuned in Phase 4) -----------------------------------
PORT_SCAN_PORTS = 20        # distinct destination ports ...
PORT_SCAN_WINDOW = 5        # ... within this many seconds

ICMP_FLOOD_COUNT = 50       # echo requests ...
ICMP_FLOOD_WINDOW = 5       # ... within this many seconds

SYN_FLOOD_COUNT = 100       # SYN packets to one ip:port ...
SYN_FLOOD_WINDOW = 5        # ... within this many seconds

BRUTE_FORCE_COUNT = 10      # new connections to one login port ...
BRUTE_FORCE_WINDOW = 30     # ... within this many seconds
LOGIN_PORTS = {21, 22, 23, 3389, 3306, 5900}

ALERT_COOLDOWN = 30         # max one alert per rule per source in this time
# -----------------------------------------------------------------------

MAX_WINDOW = max(PORT_SCAN_WINDOW, ICMP_FLOOD_WINDOW,
                 SYN_FLOOD_WINDOW, BRUTE_FORCE_WINDOW)


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
    def __init__(self):
        self.scan: Dict[str, deque] = defaultdict(deque)    # src -> (ts, dst_port)
        self.icmp: Dict[str, deque] = defaultdict(deque)    # src -> ts
        self.syn: Dict[tuple, deque] = defaultdict(deque)   # (dst_ip, dst_port) -> ts
        self.brute: Dict[tuple, deque] = defaultdict(deque) # (src, dst_ip, dst_port) -> ts
        self.last_alert: Dict[tuple, float] = {}
        self._seen = 0

    # ------------------------------------------------------------------
    def process(self, p: PacketInfo) -> List[Alert]:
        self._seen += 1
        if self._seen % 5000 == 0:
            self._cleanup(p.timestamp)

        found: List[Optional[Alert]] = []
        if p.protocol == "TCP" and self._is_syn(p):
            found += [self._port_scan(p), self._syn_flood(p), self._brute_force(p)]
        elif p.protocol == "ICMP" and p.icmp_type == 8:   # echo request
            found.append(self._icmp_flood(p))
        return [a for a in found if a]

    # ------------------------------------------------------------------
    @staticmethod
    def _is_syn(p: PacketInfo) -> bool:
        """New connection attempt: SYN set, ACK not set."""
        return bool(p.flags) and "S" in p.flags and "A" not in p.flags

    def _allowed(self, rule: str, key: str, now: float) -> bool:
        """Rate limit: one alert per (rule, key) every ALERT_COOLDOWN seconds."""
        k = (rule, key)
        if now - self.last_alert.get(k, -ALERT_COOLDOWN) < ALERT_COOLDOWN:
            return False
        self.last_alert[k] = now
        return True

    @staticmethod
    def _alert(p: PacketInfo, rule: str, severity: str, text: str) -> Alert:
        return Alert(datetime.fromtimestamp(p.timestamp).isoformat(timespec="seconds"),
                     rule, severity, p.src_ip, p.dst_ip, text)

    # ---- rules -------------------------------------------------------
    def _port_scan(self, p: PacketInfo) -> Optional[Alert]:
        dq = self.scan[p.src_ip]
        dq.append((p.timestamp, p.dst_port))
        _slide(dq, p.timestamp, PORT_SCAN_WINDOW, key=lambda x: x[0])
        ports = {port for _, port in dq}
        if len(ports) >= PORT_SCAN_PORTS and self._allowed("Port Scan", p.src_ip, p.timestamp):
            return self._alert(p, "Port Scan", "HIGH",
                               f"{len(ports)} distinct ports probed in {PORT_SCAN_WINDOW}s")
        return None

    def _icmp_flood(self, p: PacketInfo) -> Optional[Alert]:
        dq = self.icmp[p.src_ip]
        dq.append(p.timestamp)
        _slide(dq, p.timestamp, ICMP_FLOOD_WINDOW)
        if len(dq) >= ICMP_FLOOD_COUNT and self._allowed("ICMP Flood", p.src_ip, p.timestamp):
            return self._alert(p, "ICMP Flood", "MEDIUM",
                               f"{len(dq)} echo requests in {ICMP_FLOOD_WINDOW}s")
        return None

    def _syn_flood(self, p: PacketInfo) -> Optional[Alert]:
        target = (p.dst_ip, p.dst_port)
        dq = self.syn[target]
        dq.append(p.timestamp)
        _slide(dq, p.timestamp, SYN_FLOOD_WINDOW)
        if len(dq) >= SYN_FLOOD_COUNT and self._allowed("SYN Flood", f"{target}", p.timestamp):
            return self._alert(p, "SYN Flood", "CRITICAL",
                               f"{len(dq)} SYN packets to {p.dst_ip}:{p.dst_port} in {SYN_FLOOD_WINDOW}s")
        return None

    def _brute_force(self, p: PacketInfo) -> Optional[Alert]:
        if p.dst_port not in LOGIN_PORTS:
            return None
        key = (p.src_ip, p.dst_ip, p.dst_port)
        dq = self.brute[key]
        dq.append(p.timestamp)
        _slide(dq, p.timestamp, BRUTE_FORCE_WINDOW)
        if len(dq) >= BRUTE_FORCE_COUNT and self._allowed("Brute Force Attempt", f"{key}", p.timestamp):
            return self._alert(p, "Brute Force Attempt", "HIGH",
                               f"{len(dq)} connections to login port {p.dst_port} in {BRUTE_FORCE_WINDOW}s")
        return None

    # ------------------------------------------------------------------
    def _cleanup(self, now: float) -> None:
        """Forget sources that have been quiet, so memory stays small."""
        cutoff = now - MAX_WINDOW
        tables = (
            (self.scan, lambda e: e[0]),   # entries are (timestamp, port)
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
            if self.last_alert[k] < now - ALERT_COOLDOWN:
                del self.last_alert[k]