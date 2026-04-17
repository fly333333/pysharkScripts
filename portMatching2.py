import sys
import pyshark

# Citation: Used Scott Kirlin's "listProtocols.py" for starters.
# Adding to "insecureProtocols.py" script for this one.

class NetworkProtocol:
    def __init__(self, name, default_port):
        self.name = name
        self.default_port = str(default_port)

    def port_match(self, packet):
        if hasattr(packet, 'tcp'):
            if packet.tcp.srcport == self.default_port or packet.tcp.dstport == self.default_port:
                return True
        return False

protocolList = [
    NetworkProtocol("HTTP", 80),
    NetworkProtocol("TELNET", 23),
    NetworkProtocol("SSH", 22),
    NetworkProtocol("TLS", 443)
]

def main():
    fileName = sys.argv[1]
    capture = pyshark.FileCapture(fileName)
    for packet in capture:
        if not hasattr(packet, 'ip'):
            continue

        packet_layers = [layer.layer_name.upper() for layer in packet.layers]

        dest_port = "N/A"
        if hasattr(packet, 'tcp'):
            dest_port = packet.tcp.dstport
        elif hasattr(packet, 'udp'):
            dest_port = packet.udp.dstport

        for knownProtocol in protocolList:
            if dest_port == knownProtocol.default_port:
                if knownProtocol.name not in packet_layers:
                    print(f"Wrong Service On Port:")
                    print(f"    Packet {packet.number}: Port {dest_port} is reserved for {knownProtocol.name},")
                    print(f"    but the packet contains: {packet.highest_layer.upper()}")
                    print(f"    Connection: {packet.ip.src} -> {packet.ip.dst}\n")
    capture.close()

if __name__ == "__main__":
    main()
