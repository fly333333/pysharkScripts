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
    capture = pyshark.FileCapture(fileName, decode_as={'tcp.port==8080': 'telnet'})
    for packet in capture:
        if not hasattr(packet, 'ip'):
            continue

        packet_layers = [layer.layer_name.upper() for layer in packet.layers]

        for knownProtocol in protocolList:
            if knownProtocol.name in packet_layers:

                if not knownProtocol.port_match(packet):
                    actualPort = packet.tcp.dstport if hasattr(packet, 'tcp') else "N/A"

                    print(f"PORT MISMATCH FOUND:")
                    print(f"  Packet {packet.number}: {knownProtocol.name} detected on non-standard port!")
                    print(f"  Source IP: {packet.ip.src} -> Dest IP: {packet.ip.dst}")
                    print(f"  Detected Port: {actualPort}")
                    print(f"  Expected Port: {knownProtocol.default_port}")
    capture.close()

if __name__ == "__main__":
    main()
