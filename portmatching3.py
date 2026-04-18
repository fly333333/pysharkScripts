import sys
import pyshark

class NetworkProtocol:
    def __init__(self, name, default_port):
        self.name = name
        self.default_port = str(default_port)

protocolList = [
    NetworkProtocol("HTTP", 80),
    NetworkProtocol("TELNET", 23),
    NetworkProtocol("SSH", 22),
    NetworkProtocol("TLS", 443)
    NetworkProtocol("DNS", 53)

]

def main():
    fileName = sys.argv[1]
    capture = pyshark.FileCapture(fileName)
    for packet in capture:

        # Not an IP Packet, skip.
        if not hasattr(packet, 'ip'):
            continue

        # Get the Layers within the Packet.
        packet_layers = [layer.layer_name.upper() for layer in packet.layers]

        # Set udp/tcp destination port.
        dest_port = "N/A"
        if hasattr(packet, 'tcp'):
            dest_port = packet.tcp.dstport
        elif hasattr(packet, 'udp'):
            dest_port = packet.udp.dstport

        # Core check for mismatched ports/services.
        for knownProtocol in protocolList:
            if dest_port == knownProtocol.default_port:
                if knownProtocol.name not in packet_layers:
                    print(f"Wrong Service On Port:")
                    print(f"    Packet {packet.number}: Port {dest_port} is for {knownProtocol.name},")
                    print(f"    but the packet contains: {packet_layers}")
                    print(f"    Connection: {packet.ip.src} -> {packet.ip.dst}")

                # Check if the packet has a TCP length of 0. If so, this means this packet is a handshake, a scan (i.e. RST flag), or empty.
                # I previously had this above the check, however, its more valuable to mention after the check, rather than skip the check if it a Handshake.
                tcp_payload_len = int(getattr(packet.tcp, 'len', 0))
                if tcp_payload_len == 0:
                    print(f"Packet {packet.number} with Port {dest_port} has TCP length 0. Potential Handshake, Scanning or otherwise empty TCP packet.\n")

    capture.close()

if __name__ == "__main__":
    main()
