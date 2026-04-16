import sys
import asyncio
import pyshark

# Citation: Used Scott Kirlin's "listProtocols.py" for starters.

suspectProtocols = {"FTP", "TELNET", "HTTP"}

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
    asyncio.run(main())
