#!/usr/bin/env python3
"""
TCP Packet Generator on Port 80
Uses Scapy to craft and send TCP packets.
Requires root/admin privileges and: pip install scapy
"""

from scapy.all import IP, TCP, send, RandShort
import argparse


def generate_tcp_packet(
    dst_ip: str,
    src_ip: str = "192.168.1.100",
    dst_port: int = 80,
    flags: str = "S",
    count: int = 1,
    verbose: bool = True,
):
    """
    Craft and send a raw TCP packet.

    Args:
        dst_ip:   Destination IP address
        src_ip:   Source IP address (spoofed)
        dst_port: Destination port (default 80)
        flags:    TCP flags string, e.g. 'S' (SYN), 'A' (ACK), 'SA' (SYN-ACK),
                  'F' (FIN), 'R' (RST)
        count:    Number of packets to send
        verbose:  Print packet summary
    """
    ip_layer  = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=RandShort(), dport=dst_port, flags=flags)
    packet    = ip_layer / tcp_layer

    if verbose:
        print(f"Sending {count} packet(s) to {dst_ip}:{dst_port}  flags={flags!r}")
        packet.show2()

    send(packet, count=count, verbose=verbose)
    print(f"✓ Sent {count} TCP packet(s).")


# ---------------------------------------------------------------------------
# Preset packet types
# ---------------------------------------------------------------------------

def send_syn(dst_ip: str, count: int = 1):
    """Classic TCP SYN (connection initiation)."""
    generate_tcp_packet(dst_ip, flags="S", count=count)


def send_ack(dst_ip: str, count: int = 1):
    """TCP ACK."""
    generate_tcp_packet(dst_ip, flags="A", count=count)


def send_fin(dst_ip: str, count: int = 1):
    """TCP FIN (graceful teardown)."""
    generate_tcp_packet(dst_ip, flags="FA", count=count)


def send_rst(dst_ip: str, count: int = 1):
    """TCP RST (hard reset)."""
    generate_tcp_packet(dst_ip, flags="R", count=count)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate raw TCP packets on port 80 using Scapy."
    )
    parser.add_argument("dst_ip", help="Destination IP address")
    parser.add_argument(
        "--type",
        choices=["syn", "ack", "fin", "rst", "custom"],
        default="syn",
        help="Packet type to send (default: syn)",
    )
    parser.add_argument("--flags", default="S",  help="Custom TCP flags (used with --type custom)")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    args = parser.parse_args()

    dispatch = {
        "syn":    lambda: send_syn(args.dst_ip, args.count),
        "ack":    lambda: send_ack(args.dst_ip, args.count),
        "fin":    lambda: send_fin(args.dst_ip, args.count),
        "rst":    lambda: send_rst(args.dst_ip, args.count),
        "custom": lambda: generate_tcp_packet(args.dst_ip, flags=args.flags, count=args.count),
    }
    dispatch[args.type]()


if __name__ == "__main__":
    main()
