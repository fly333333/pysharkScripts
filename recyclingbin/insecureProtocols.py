import sys
import pyshark

# Citation: Used Scott Kirlin's "listProtocols.py" for starters.

suspectProtocols = {"FTP", "TELNET", "HTTP", "SSL"}

def main():
    fileName = sys.argv[1]
    capture = pyshark.FileCapture(fileName)

    for packet in capture:
        protocol = packet.highest_layer

        if protocol in suspectProtocols:
            print(f"""Packet {packet.number}: {protocol}
                Source IP: {packet.ip.src}
                Dest IP: {packet.ip.dst}
            """)
    capture.close()

if __name__ == "__main__":
    main()
