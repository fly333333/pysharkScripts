from scapy.all import rdpcap, wrpcap, TCP

# Load your original capture
packets = rdpcap('testpcaps/corruptTelnet.cap')

# Loop through and change the port on some packets
for i, pkt in enumerate(packets):
    if pkt.haslayer(TCP) and (pkt[TCP].dport == 23 or pkt[TCP].sport == 23):
        # Change every 3rd packet to port 8080 instead of 23
        if i % 3 == 0:
            if pkt[TCP].dport == 23:
                pkt[TCP].dport = 8080
            else:
                pkt[TCP].sport = 8080

            # Delete checksums; Scapy will recalculate them automatically
            del pkt[TCP].chksum
            del pkt.getlayer('IP').chksum

# Save the modified version
wrpcap('mismatched_telnet.cap', packets)
print("Done! Created mismatched_telnet.cap")
