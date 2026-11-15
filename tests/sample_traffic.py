"""A small, fixed capture used to test SentinelAI without any live traffic.

It contains normal browsing/DNS/ping traffic followed by one example of each
attack, with the same timestamps every time. Replaying it must always give
exactly EXPECTED_ALERTS.

Save it as a capture file you can open in Wireshark or replay yourself:
    ./venv/bin/python -m tests.sample_traffic tests/data/sample_attacks.pcap
    ./venv/bin/python -m detection.replay tests/data/sample_attacks.pcap
"""
import sys
from pathlib import Path

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, wrpcap

T0 = 1_700_000_000.0
CLIENT, VICTIM, ATTACKER, GATEWAY = "10.0.0.20", "10.0.0.5", "10.0.0.66", "10.0.0.1"
GATEWAY_MAC, FORGED_MAC = "52:54:00:aa:bb:01", "de:ad:be:ef:00:66"
MAC_DST = "02:00:00:00:00:02"      # fixed, so Scapy never tries to look MAC addresses up

EXPECTED_ALERTS = ["Port Scan", "Stealth Scan", "ICMP Flood", "Brute Force Attempt",
                   "SYN Flood", "Slow Port Scan", "ARP Spoofing"]


def events():
    """Return a time-ordered list of simple tuples describing every packet."""
    ev = []

    # normal traffic: 30 web connections, 20 DNS lookups, 5 pings (about 60 s)
    for i in range(30):
        t, sp = T0 + i * 2, 50000 + i
        ev += [(t, "tcp", CLIENT, VICTIM, sp, 443, "S"),
               (t + 0.001, "tcp", VICTIM, CLIENT, 443, sp, "SA"),
               (t + 0.002, "tcp", CLIENT, VICTIM, sp, 443, "A"),
               (t + 0.050, "tcp", CLIENT, VICTIM, sp, 443, "PA"),
               (t + 0.900, "tcp", CLIENT, VICTIM, sp, 443, "FA")]
    ev += [(T0 + i * 3, "udp", CLIENT, "10.0.0.53", 40000 + i, 53) for i in range(20)]
    ev += [(T0 + i * 10, "icmp", CLIENT, VICTIM, 8) for i in range(5)]

    # 1. fast port scan: 200 ports in about one second
    ev += [(T0 + 100 + i * 0.005, "tcp", ATTACKER, VICTIM, 40000, i + 1, "S") for i in range(200)]
    # 2. FIN scan (stealth): 100 ports
    ev += [(T0 + 200 + i * 0.01, "tcp", ATTACKER, VICTIM, 40001, i + 1, "F") for i in range(100)]
    # 3. ICMP flood: 200 echo requests in one second
    ev += [(T0 + 300 + i * 0.005, "icmp", ATTACKER, VICTIM, 8) for i in range(200)]
    # 4. SSH brute force: 15 connection attempts in 3 seconds
    ev += [(T0 + 400 + i * 0.2, "tcp", ATTACKER, VICTIM, 41000 + i, 22, "S") for i in range(15)]
    # 5. SYN flood: 300 SYNs to one port from 100 spoofed sources
    ev += [(T0 + 500 + i * 0.005, "tcp", f"172.16.0.{i % 100 + 1}", VICTIM, 1024 + i, 80, "S")
           for i in range(300)]
    # 6. slow port scan: 40 ports, one every 1.6 seconds (about a minute)
    ev += [(T0 + 600 + i * 1.6, "tcp", ATTACKER, VICTIM, 42000, 1000 + i, "S") for i in range(40)]
    # 7. ARP spoofing: the gateway's address suddenly has a different MAC
    ev += [(T0 + 800 + i, "arp", GATEWAY, CLIENT, GATEWAY_MAC) for i in range(3)]
    ev += [(T0 + 810, "arp", GATEWAY, CLIENT, FORGED_MAC)]

    return sorted(ev, key=lambda e: e[0])


def to_packet(e):
    t, kind = e[0], e[1]
    if kind == "tcp":
        _, _, src, dst, sport, dport, flags = e
        pkt = Ether(dst=MAC_DST) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    elif kind == "udp":
        _, _, src, dst, sport, dport = e
        pkt = Ether(dst=MAC_DST) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    elif kind == "icmp":
        _, _, src, dst, icmp_type = e
        pkt = Ether(dst=MAC_DST) / IP(src=src, dst=dst) / ICMP(type=icmp_type)
    else:  # arp
        _, _, ip, dst, mac = e
        pkt = Ether(src=mac, dst=MAC_DST) / ARP(op=2, psrc=ip, hwsrc=mac, pdst=dst)
    pkt.time = t
    return pkt


def write_pcap(path) -> int:
    """Write the capture file and return how many packets it holds."""
    packets = [to_packet(e) for e in events()]
    wrpcap(str(path), packets)
    return len(packets)


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/data/sample_attacks.pcap")
    out.parent.mkdir(parents=True, exist_ok=True)
    print(f"Wrote {write_pcap(out)} packets to {out}")