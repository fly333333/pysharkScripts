import sys
import pyshark

# Used claude to  combine previous code with my new code, and partition functionality.

class NetworkProtocol:
    def __init__(self, name, default_port):
        self.name = name
        self.default_port = str(default_port)

protocolList = [
    NetworkProtocol("HTTP", 80),
    NetworkProtocol("TELNET", 23),
    NetworkProtocol("SSH", 22),
    NetworkProtocol("TLS", 443),
    NetworkProtocol("DNS", 53)
]

# Hex version codes mapped to human-readable names.
VULNERABLE_VERSIONS = {
    "TLS": {
        "0x0300": "SSL 3.0",
        "0x0301": "TLS 1.0",
        "0x0302": "TLS 1.1",
    }
}

def get_protocol_version(packet, protocol_name):
    """Extract the version field from a packet for a given protocol."""
    if protocol_name == "TLS" and hasattr(packet, 'tls'):
        version = getattr(packet.tls, 'record_version', None)
        return version
    return None

def packet_checks(packet, packet_layers, dest_port):
    """Check if the destination port matches the expected protocol layer."""
    for knownProtocol in protocolList:
        if dest_port == knownProtocol.default_port:
            if knownProtocol.name not in packet_layers:
                print(f"Wrong Service On Port:")
                print(f"    Packet {packet.number}: Port {dest_port} is for {knownProtocol.name},")
                print(f"    but the packet contains: {packet_layers}")
                print(f"    Connection: {packet.ip.src} -> {packet.ip.dst}")

            # Check for vulnerable protocol versions.
            if knownProtocol.name in VULNERABLE_VERSIONS:
                version = get_protocol_version(packet, knownProtocol.name)
                if version and version in VULNERABLE_VERSIONS[knownProtocol.name]:
                    version_name = VULNERABLE_VERSIONS[knownProtocol.name][version]
                    print(f"Vulnerable Version Detected:")
                    print(f"    Packet {packet.number}: {knownProtocol.name} version is {version_name} ({version})")
                    print(f"    Connection: {packet.ip.src} -> {packet.ip.dst}")

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
        packet_checks(packet, packet_layers, dest_port)

        # Check if the packet has a TCP length of 0. If so, this means this packet is a handshake, a scan (i.e. RST flag), or empty.
        # I previously had this above the check, however, its more valuable to mention after the check, rather than skip the check if it a Handshake.
        if hasattr(packet, 'tcp'):
            tcp_payload_len = int(getattr(packet.tcp, 'len', -1))
            for knownProtocol in protocolList:
                if dest_port == knownProtocol.default_port and tcp_payload_len == 0:
                    print(f"Packet {packet.number} with Port {dest_port} has TCP length 0. Potential Handshake, Scanning or otherwise empty TCP packet.\n")

    capture.close()

if __name__ == "__main__":
    main()
