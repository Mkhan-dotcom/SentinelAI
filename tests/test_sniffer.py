"""Unit tests for packet parsing and the duplicate filter.

These build real packets with Scapy (nothing is sent on the network), so no
root is needed.

Run from the project root:   ./venv/bin/python -m pytest -q
"""
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw

from detection.rules import Detector
from sniffer.sniffer import DuplicateFilter, format_packet, parse_packet

A, B = "10.0.0.1", "10.0.0.2"


def wire(layers, t):
    """Build the packet and read it back, the way a sniffer would see it."""
    pkt = Ether(bytes(layers))
    pkt.time = t
    return pkt


# ------------------------------------------------------------------ parsing
def test_parse_tcp_syn():
    p = parse_packet(wire(Ether() / IP(src=A, dst=B) / TCP(sport=1234, dport=80, flags="S"), 100.5))
    assert (p.protocol, p.src_ip, p.dst_ip) == ("TCP", A, B)
    assert (p.src_port, p.dst_port, p.flags) == (1234, 80, "S")
    assert p.icmp_type is None and p.timestamp == 100.5


def test_parse_null_and_xmas_flags():
    null = parse_packet(wire(Ether() / IP(src=A, dst=B) / TCP(dport=80, flags=0), 1))
    xmas = parse_packet(wire(Ether() / IP(src=A, dst=B) / TCP(dport=80, flags="FPU"), 1))
    assert null.flags == ""
    assert set(xmas.flags) == {"F", "P", "U"}


def test_parse_udp():
    p = parse_packet(wire(Ether() / IP(src=A, dst=B) / UDP(sport=5000, dport=123), 1))
    assert (p.protocol, p.src_port, p.dst_port, p.flags) == ("UDP", 5000, 123, None)


def test_parse_icmp_echo_request():
    p = parse_packet(wire(Ether() / IP(src=A, dst=B) / ICMP(type=8), 1))
    assert (p.protocol, p.icmp_type, p.src_port, p.dst_port) == ("ICMP", 8, None, None)


def test_parse_arp_keeps_the_sender_mac():
    pkt = Ether() / ARP(op=2, psrc="10.0.2.2", hwsrc="52:55:0a:00:02:02", pdst="10.0.2.15")
    p = parse_packet(wire(pkt, 1))
    assert (p.protocol, p.src_ip, p.flags) == ("ARP", "10.0.2.2", "op=2")
    assert p.src_mac == "52:55:0a:00:02:02"


def test_non_ip_traffic_is_ignored():
    assert parse_packet(wire(Ether(type=0x88B5) / Raw(load=b"hello"), 1)) is None


def test_format_packet_shows_the_main_fields():
    p = parse_packet(wire(Ether() / IP(src=A, dst=B) / TCP(dport=22, flags="S"), 1))
    text = format_packet(p)
    assert A in text and B in text and "22" in text


# --------------------------------------------------------- duplicate filter
def syn(i, t, ip_id=0):
    return wire(Ether() / IP(src=A, dst=B, id=ip_id) / TCP(sport=40000 + i, dport=22, flags="S", seq=i), t)


def echo(seq, t):
    return wire(Ether() / IP(src=A, dst=B, id=seq) / ICMP(type=8, id=7, seq=seq), t)


def test_second_copy_of_a_packet_is_dropped():
    f = DuplicateFilter()
    assert f.is_duplicate(echo(1, 100.000000)) is False
    assert f.is_duplicate(echo(1, 100.000020)) is True


def test_different_packets_close_together_are_kept():
    f = DuplicateFilter()
    assert [f.is_duplicate(echo(n, 100 + n * 0.00005)) for n in range(1, 50)] == [False] * 49


def test_same_packet_a_second_later_is_kept():
    f = DuplicateFilter()
    assert f.is_duplicate(syn(1, 100.0)) is False
    assert f.is_duplicate(syn(1, 101.0)) is False


def test_duplicate_filter_ignores_non_ip_packets():
    f = DuplicateFilter()
    arp = Ether() / ARP(op=2, psrc="10.0.2.2", hwsrc="52:55:0a:00:02:02", pdst="10.0.2.15")
    assert f.is_duplicate(wire(arp, 1)) is False
    assert f.is_duplicate(wire(arp, 1.00001)) is False


def test_loopback_doubling_does_not_cause_false_alarms():
    """Regression test: every loopback packet is captured twice. Eight real
    connections to the SSH port must not look like sixteen."""
    def run(count):
        f, det, out = DuplicateFilter(), Detector(), []
        for i in range(count):
            for copy in range(2):                       # each packet arrives twice
                pkt = syn(i, 100 + i * 0.2 + copy * 0.00002)
                if f.is_duplicate(pkt):
                    continue
                out += det.process(parse_packet(pkt))
        return [a.rule for a in out]
    assert run(8) == []
    assert run(10) == ["Brute Force Attempt"]