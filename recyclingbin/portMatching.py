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

        highestProtocol = packet.highest_layer

        for knownProtocol in protocolList:

            if knownProtocol.name == highestProtocol:

                if not knownProtocol.port_match(packet):
                    actualPort = packet.tcp.dstport if hasattr(packet, 'tcp') else "N/A"

                    print(f""" PORT MISMATCH FOUND:
                        Packet {packet.number}: {highestProtocol}
                        Source IP: {packet.ip.src}
                        Dest IP: {packet.ip.dst}
                        Detected Port: {actualPort}
                        Needed Port: {knownProtocol.default_port}
                    """)
    capture.close()

if __name__ == "__main__":
    main()
