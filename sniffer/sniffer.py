#!/usr/bin/env python3
"""SentinelAI Phase 1 - Packet Sniffer"""
import argparse
import socket
import time
from dataclasses import dataclass
from typing import Callable, Optional
from scapy.all import sniff, conf, IP, IPv6, TCP, UDP, ICMP, ARP

# Kernel receive buffer for the capture socket. The default (about 200 KB)
# overflows during very fast bursts (e.g. `ping -f`) and packets are lost
# before Python sees them. A limit this size is only used when needed.
CAPTURE_BUFFER_BYTES = 64 * 1024 * 1024


@dataclass
class PacketInfo:
    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    size: int
    flags: Optional[str]
    icmp_type: Optional[int]
    src_mac: Optional[str] = None      # sender MAC address (used for ARP)


class DuplicateFilter:
    """Drops the second copy of a packet.

    On the Linux loopback interface (lo) the capture socket sees every packet
    twice (once leaving, once arriving), which doubles every count in the
    detector. Two packets are treated as copies only if all their header
    fields match AND they were captured within `window` seconds of each other.
    """

    def __init__(self, window: float = 0.005):
        self.window = window
        self._last = {}
        self._n = 0

    @staticmethod
    def _key(pkt):
        if pkt.haslayer(IP):
            ip = pkt[IP]
            key = (ip.src, ip.dst, ip.id, ip.proto, ip.len)
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
            key = (ip.src, ip.dst, ip.fl, ip.nh, ip.plen)
        else:
            return None
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            key += (t.sport, t.dport, int(t.seq), int(t.ack), int(t.flags))
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            key += (u.sport, u.dport, u.len)
        elif pkt.haslayer(ICMP):
            c = pkt[ICMP]
            key += (c.type, c.code, getattr(c, "id", 0), getattr(c, "seq", 0))
        return key

    def is_duplicate(self, pkt) -> bool:
        try:
            key = self._key(pkt)
        except Exception:
            return False
        if key is None:
            return False
        now = float(pkt.time)
        last = self._last.get(key)
        self._last[key] = now
        self._n += 1
        if self._n % 1000 == 0:          # forget old entries now and then
            cutoff = now - 1.0
            self._last = {k: v for k, v in self._last.items() if v >= cutoff}
        return last is not None and 0 <= now - last <= self.window


def open_capture_socket(iface=None, bpf_filter=None):
    """Open a capture socket with a large kernel buffer so bursts are not dropped."""
    sock = conf.L2listen(iface=iface, filter=bpf_filter)
    for opt in (getattr(socket, "SO_RCVBUFFORCE", 33), socket.SO_RCVBUF):
        try:
            sock.ins.setsockopt(socket.SOL_SOCKET, opt, CAPTURE_BUFFER_BYTES)
            break
        except (OSError, AttributeError):
            continue                      # keep the default buffer if both fail
    return sock


def parse_packet(pkt) -> Optional[PacketInfo]:
    ts, size = float(pkt.time), len(pkt)
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        return PacketInfo(ts, "ARP", a.psrc, a.pdst, None, None, size, f"op={a.op}", None, a.hwsrc)
    if pkt.haslayer(IP):
        ip = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
    else:
        return None
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        return PacketInfo(ts, "TCP", ip.src, ip.dst, t.sport, t.dport, size, str(t.flags), None)
    if pkt.haslayer(UDP):
        u = pkt[UDP]
        return PacketInfo(ts, "UDP", ip.src, ip.dst, u.sport, u.dport, size, None, None)
    if pkt.haslayer(ICMP):
        return PacketInfo(ts, "ICMP", ip.src, ip.dst, None, None, size, None, pkt[ICMP].type)
    return PacketInfo(ts, "OTHER", ip.src, ip.dst, None, None, size, None, None)


def format_packet(p: PacketInfo) -> str:
    s = f"[+] {p.protocol:<4} Packet | Src: {p.src_ip} | Dst: {p.dst_ip}"
    if p.dst_port is not None:
        s += f" | Port: {p.dst_port}"
    if p.flags:
        s += f" | Flags: {p.flags}"
    if p.icmp_type is not None:
        s += f" | ICMP type: {p.icmp_type}"
    return s + f" | Size: {p.size}B"


def start_sniffing(iface=None, bpf_filter=None, count=0,
                   on_packet: Optional[Callable] = None, verbose=True):
    dedup = DuplicateFilter() if iface == "lo" else None

    def handle(pkt):
        if dedup and dedup.is_duplicate(pkt):
            return
        info = parse_packet(pkt)
        if info is None:
            return
        if verbose:
            print(format_packet(info))
        if on_packet:
            on_packet(info)
    sock = open_capture_socket(iface, bpf_filter)
    try:
        sniff(opened_socket=sock, prn=handle, store=False, count=count)
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser(description="SentinelAI packet sniffer")
    ap.add_argument("-i", "--iface", help="interface, e.g. enp0s3")
    ap.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp port 80"')
    ap.add_argument("-c", "--count", type=int, default=0, help="0 = unlimited")
    a = ap.parse_args()
    print(f"[*] Sniffing started {time.strftime('%H:%M:%S')} "
          f"(iface={a.iface or 'default'}, filter={a.filter or 'none'}) - Ctrl+C to stop\n")
    try:
        start_sniffing(a.iface, a.filter, a.count)
    except PermissionError:
        print("[!] Run with sudo")
    except KeyboardInterrupt:
        print("\n[*] Stopped.")


if __name__ == "__main__":
    main()