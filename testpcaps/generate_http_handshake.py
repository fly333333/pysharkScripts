#!/usr/bin/env python3
"""
HTTP/TCP Packet Generator with Full TCP Handshake on Port 80
Performs a proper SYN -> SYN-ACK -> ACK handshake before sending HTTP payload.

Requires:
  - Root/admin privileges
  - pip install scapy
  - Block kernel RST responses BEFORE running (kernel will reset connections
    it didn't open). Run this iptables rule first:
      sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
  - To remove the rule after:
      sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP
"""

import sys
import random
import argparse
from scapy.all import IP, TCP, sr1, send, RandShort, conf

# Suppress Scapy output unless verbose
conf.verb = 0

DIVIDER = "-" * 50


def tcp_handshake_and_send(
    dst_ip: str,
    http_payload: str,
    dst_port: int = 80,
    src_ip: str = None,
    timeout: int = 5,
    verbose: bool = True,
):
    """
    Perform a full TCP three-way handshake then send an HTTP payload.

    Steps:
      1. SYN        ->
      2.            <- SYN-ACK
      3. ACK        ->
      4. PSH+ACK    -> (HTTP request)
      5.            <- PSH+ACK (HTTP response, printed if verbose)
      6. FIN+ACK    ->
      7.            <- FIN+ACK
      8. ACK        ->

    Args:
        dst_ip:       Destination IP address
        http_payload: Raw HTTP request string
        dst_port:     Destination port (default 80)
        src_ip:       Source IP (defaults to Scapy auto-select)
        timeout:      Seconds to wait for each response
        verbose:      Print step-by-step progress and response
    """

    def log(msg):
        if verbose:
            print(msg)

    sport = int(RandShort())
    seq   = random.randint(1000, 65000)

    ip = IP(dst=dst_ip)
    if src_ip:
        ip.src = src_ip

    # ------------------------------------------------------------------
    # Step 1: SYN
    # ------------------------------------------------------------------
    log(f"\n[1/6] Sending SYN -> {dst_ip}:{dst_port}  seq={seq}")
    syn     = TCP(sport=sport, dport=dst_port, flags="S", seq=seq)
    syn_ack = sr1(ip / syn, timeout=timeout)

    if syn_ack is None:
        print("X No response to SYN. Check the destination and your iptables rule.")
        sys.exit(1)
    if not (syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12):  # SYN-ACK = 0x12
        print(f"X Expected SYN-ACK, got flags={syn_ack[TCP].flags:#x}. Aborting.")
        sys.exit(1)

    log(f"[2/6] Received SYN-ACK <- seq={syn_ack[TCP].seq}  ack={syn_ack[TCP].ack}")

    server_seq = syn_ack[TCP].seq
    client_seq = syn_ack[TCP].ack  # server's ack is our next seq

    # ------------------------------------------------------------------
    # Step 3: ACK  (completes handshake)
    # ------------------------------------------------------------------
    log("[3/6] Sending ACK -> (handshake complete)")
    ack = TCP(
        sport=sport, dport=dst_port, flags="A",
        seq=client_seq, ack=server_seq + 1
    )
    send(ip / ack)

    # ------------------------------------------------------------------
    # Step 4: PSH+ACK with HTTP payload
    # ------------------------------------------------------------------
    log(f"[4/6] Sending HTTP request (PSH+ACK) ->\n{DIVIDER}")
    if verbose:
        print(http_payload.rstrip())
        print(DIVIDER)

    http_pkt = TCP(
        sport=sport, dport=dst_port, flags="PA",
        seq=client_seq, ack=server_seq + 1
    )
    response = sr1(ip / http_pkt / http_payload, timeout=timeout)

    if response is None:
        print("X No HTTP response received.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Step 5: Print response -- safely handle missing Raw layer
    # ------------------------------------------------------------------
    log(f"[5/6] Received HTTP response <-\n{DIVIDER}")
    raw_payload = response["Raw"].load if response.haslayer("Raw") else b""
    if verbose:
        if raw_payload:
            print(raw_payload.decode(errors="replace"))
        else:
            print("(no body in response)")
        print(DIVIDER)

    server_seq2 = response[TCP].seq
    client_seq2 = response[TCP].ack
    raw_len     = len(raw_payload)

    # ------------------------------------------------------------------
    # Step 6: FIN+ACK (begin graceful teardown)
    # ------------------------------------------------------------------
    log("[6/6] Sending FIN+ACK -> (teardown)")
    fin = TCP(
        sport=sport, dport=dst_port, flags="FA",
        seq=client_seq2, ack=server_seq2 + raw_len
    )
    fin_ack = sr1(ip / fin, timeout=timeout)

    if fin_ack and fin_ack.haslayer(TCP):
        final_ack = TCP(
            sport=sport, dport=dst_port, flags="A",
            seq=fin_ack[TCP].ack, ack=fin_ack[TCP].seq + 1
        )
        send(ip / final_ack)
        log("      Final ACK sent. Connection closed cleanly.")
    else:
        log("      No FIN-ACK received -- connection may have been reset by server.")

    print("\nDone.")


# ---------------------------------------------------------------------------
# HTTP request builders
# ---------------------------------------------------------------------------

def build_get(host: str, path: str) -> str:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: TCPHandshake/1.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )


def build_post(host: str, path: str, body: str) -> str:
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: TCPHandshake/1.0\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
        f"{body}"
    )


def build_head(host: str, path: str) -> str:
    return (
        f"HEAD {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: TCPHandshake/1.0\r\n"
        f"Connection: close\r\n\r\n"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Send HTTP requests over a proper TCP handshake using Scapy.\n\n"
            "IMPORTANT: Before running, suppress kernel RST responses:\n"
            "  sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP\n"
            "Remove after:\n"
            "  sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("dst_ip",  help="Destination IP address")
    parser.add_argument(
        "--method",
        choices=["GET", "POST", "HEAD"],
        default="GET",
        help="HTTP method (default: GET)",
    )
    parser.add_argument("--host",    default="",  help="HTTP Host header (defaults to dst_ip)")
    parser.add_argument("--path",    default="/", help="HTTP request path (default: /)")
    parser.add_argument("--body",    default="",  help="POST body (used with --method POST)")
    parser.add_argument("--timeout", type=int, default=5, help="Per-step timeout in seconds (default: 5)")
    parser.add_argument("--quiet",   action="store_true",  help="Suppress step-by-step output")
    args = parser.parse_args()

    host = args.host or args.dst_ip

    builders = {
        "GET":  lambda: build_get(host, args.path),
        "POST": lambda: build_post(host, args.path, args.body),
        "HEAD": lambda: build_head(host, args.path),
    }
    payload = builders[args.method]()

    tcp_handshake_and_send(
        dst_ip=args.dst_ip,
        http_payload=payload,
        timeout=args.timeout,
        verbose=not args.quiet,
    )


if __name__ == "__main__":
    main()
