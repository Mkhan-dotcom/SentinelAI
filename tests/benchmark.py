"""How many packets per second can SentinelAI process?

Measures three things on this machine, with no root and no network:
  1. the rules alone (the Detector)
  2. reading and parsing packets (Scapy dissection + parse_packet)
  3. both together, which is the real limit for sustained traffic

Run from the project root:   ./venv/bin/python -m tests.benchmark
"""
import time

from scapy.all import IP, TCP, UDP, Ether

from detection.rules import Detector
from sniffer.sniffer import PacketInfo, parse_packet

RULE_PACKETS = 200_000
WIRE_PACKETS = 2_000
WIRE_REPEATS = 10
MAC = "02:00:00:00:00:02"


def fake_info(i):
    """A busy mix of packets from many different hosts."""
    return PacketInfo(1000 + i * 0.0001, "TCP", f"10.{(i // 250) % 250}.{i % 250}.{i % 200 + 1}",
                      "10.0.0.1", 40000 + i % 20000, (80, 443, 22, 8080)[i % 4], 60,
                      ("S", "SA", "A", "PA", "FA")[i % 5], None)


def real_packets():
    """Raw bytes of a mix of TCP and UDP packets, as they would arrive off the wire."""
    raw = []
    for i in range(WIRE_PACKETS):
        src, dst = f"10.0.{i % 200}.{i % 250 + 1}", "10.0.0.1"
        if i % 5 == 4:
            pkt = Ether(dst=MAC) / IP(src=src, dst=dst) / UDP(sport=5000 + i, dport=53)
        else:
            pkt = Ether(dst=MAC) / IP(src=src, dst=dst) / TCP(
                sport=40000 + i, dport=(80, 443, 22, 8080)[i % 4], flags=("S", "A", "PA", "FA")[i % 4])
        raw.append(bytes(pkt))
    return raw


def timed(label, count, fn):
    start = time.perf_counter()
    fn()
    seconds = time.perf_counter() - start
    rate = count / seconds
    print(f"  {label:<44} {rate:>10,.0f} packets/s")
    return rate


def main():
    print("SentinelAI throughput benchmark (single core)\n")

    infos = [fake_info(i) for i in range(RULE_PACKETS)]
    det = Detector()
    rules_rate = timed("rules only (Detector)", RULE_PACKETS,
                       lambda: [det.process(p) for p in infos])

    raw = real_packets()
    total = WIRE_PACKETS * WIRE_REPEATS

    def parse_only():
        for _ in range(WIRE_REPEATS):
            for r in raw:
                pkt = Ether(r)
                pkt.time = 1000.0
                parse_packet(pkt)

    parse_rate = timed("reading + parsing packets (Scapy)", total, parse_only)

    det2 = Detector()

    def both():
        t = 1000.0
        for _ in range(WIRE_REPEATS):
            for r in raw:
                pkt = Ether(r)
                t += 0.0001
                pkt.time = t
                info = parse_packet(pkt)
                if info:
                    det2.process(info)

    both_rate = timed("end to end (parse + all rules)", total, both)

    print(f"\n  Sustained limit on this machine: about {both_rate:,.0f} packets/s.")
    slower = "reading and parsing packets" if parse_rate < rules_rate else "the rules"
    print(f"  The slower part is {slower}.")
    print("  Short bursts above this speed are absorbed by the 64 MB capture buffer.")


if __name__ == "__main__":
    main()