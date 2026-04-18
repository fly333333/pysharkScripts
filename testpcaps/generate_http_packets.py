#!/usr/bin/env python3
"""
HTTP/TCP Packet Generator on Port 80
Uses Scapy to craft and send TCP packets carrying HTTP application-layer payloads.
Requires root/admin privileges and: pip install scapy
"""

from scapy.all import IP, TCP, send, RandShort
import argparse


def send_http_packet(
    dst_ip: str,
    src_ip: str = "192.168.1.100",
    dst_port: int = 80,
    payload: str = "",
    count: int = 1,
    verbose: bool = True,
):
    """
    Craft and send a TCP packet carrying an HTTP payload.

    Args:
        dst_ip:   Destination IP address
        src_ip:   Source IP address (spoofed)
        dst_port: Destination port (default 80)
        payload:  Raw HTTP request string
        count:    Number of packets to send
        verbose:  Print packet summary
    """
    ip_layer  = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=RandShort(), dport=dst_port, flags="PA")
    packet    = ip_layer / tcp_layer / payload

    if verbose:
        print(f"Sending {count} HTTP packet(s) to {dst_ip}:{dst_port}")
        packet.show2()

    send(packet, count=count, verbose=verbose)
    print(f"✓ Sent {count} HTTP/TCP packet(s).")


# ---------------------------------------------------------------------------
# Preset HTTP request builders
# ---------------------------------------------------------------------------

def send_get(dst_ip: str, path: str = "/", host: str = "", count: int = 1):
    """HTTP GET request."""
    host_header = host or dst_ip
    payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: HTTPGen/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )
    send_http_packet(dst_ip, payload=payload, count=count)


def send_post(dst_ip: str, path: str = "/", host: str = "", body: str = "", count: int = 1):
    """HTTP POST request."""
    host_header = host or dst_ip
    payload = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: HTTPGen/1.0\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
        f"{body}"
    )
    send_http_packet(dst_ip, payload=payload, count=count)


def send_head(dst_ip: str, path: str = "/", host: str = "", count: int = 1):
    """HTTP HEAD request."""
    host_header = host or dst_ip
    payload = (
        f"HEAD {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: HTTPGen/1.0\r\n"
        f"Connection: close\r\n\r\n"
    )
    send_http_packet(dst_ip, payload=payload, count=count)


def send_options(dst_ip: str, path: str = "*", host: str = "", count: int = 1):
    """HTTP OPTIONS request."""
    host_header = host or dst_ip
    payload = (
        f"OPTIONS {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: HTTPGen/1.0\r\n"
        f"Connection: close\r\n\r\n"
    )
    send_http_packet(dst_ip, payload=payload, count=count)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate HTTP/TCP packets on port 80 using Scapy."
    )
    parser.add_argument("dst_ip", help="Destination IP address")
    parser.add_argument(
        "--method",
        choices=["GET", "POST", "HEAD", "OPTIONS", "custom"],
        default="GET",
        help="HTTP method to use (default: GET)",
    )
    parser.add_argument("--path",    default="/",  help="HTTP request path (default: /)")
    parser.add_argument("--host",    default="",   help="HTTP Host header value (defaults to dst_ip)")
    parser.add_argument("--body",    default="",   help="POST body content (used with --method POST)")
    parser.add_argument("--payload", default="",   help="Raw HTTP payload string (used with --method custom)")
    parser.add_argument("--count",   type=int, default=1, help="Number of packets to send")
    args = parser.parse_args()

    dispatch = {
        "GET":     lambda: send_get(args.dst_ip, args.path, args.host, args.count),
        "POST":    lambda: send_post(args.dst_ip, args.path, args.host, args.body, args.count),
        "HEAD":    lambda: send_head(args.dst_ip, args.path, args.host, args.count),
        "OPTIONS": lambda: send_options(args.dst_ip, args.path, args.host, args.count),
        "custom":  lambda: send_http_packet(args.dst_ip, payload=args.payload, count=args.count),
    }
    dispatch[args.method]()


if __name__ == "__main__":
    main()
