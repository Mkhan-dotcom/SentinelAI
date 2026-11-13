#!/usr/bin/env python3
"""SentinelAI Phase 1 - Packet Sniffer"""
import argparse
import time
from dataclasses import dataclass
from typing import Callable, Optional
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP


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


def parse_packet(pkt) -> Optional[PacketInfo]:
    ts, size = float(pkt.time), len(pkt)
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        return PacketInfo(ts, "ARP", a.psrc, a.pdst, None, None, size, f"op={a.op}", None)
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
    def handle(pkt):
        info = parse_packet(pkt)
        if info is None:
            return
        if verbose:
            print(format_packet(info))
        if on_packet:
            on_packet(info)
    sniff(iface=iface, filter=bpf_filter, prn=handle, store=False, count=count)


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
