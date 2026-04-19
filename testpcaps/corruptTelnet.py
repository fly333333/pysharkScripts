from scapy.all import rdpcap, wrpcap, TCP

packets = rdpcap('telnet.cap')

# Loop through and change the port on some packets
for i, pkt in enumerate(packets):
    if pkt.haslayer(TCP) and (pkt[TCP].dport == 23 or pkt[TCP].sport == 23):
        # Change every 3rd packet to port 8080 instead of 23
        if i % 3 == 0:
            if pkt[TCP].dport == 23:
                pkt[TCP].dport = 80
            else:
                pkt[TCP].sport = 80

            del pkt[TCP].chksum
            del pkt.getlayer('IP').chksum

# Save the modified version
wrpcap('TELNET_on_port80.cap', packets)
print("Created messed up pcap")
