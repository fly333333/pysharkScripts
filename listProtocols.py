# import pyshark module
import pyshark

# create a list to store the protocols
protocols = []

# create a dictionary to store the protocol counts
protocol_counts = {}

# get the file name from the command line argument
file_name = "win.pcapng"

# open the file using pyshark.FileCapture
capture = pyshark.FileCapture(file_name)

# loop through each packet in the capture
for packet in capture:
    # get the protocol name from the packet
    protocol = packet.highest_layer

    # if the protocol is not None, add it to the list and update the dictionary
    if protocol:
        protocols.append(protocol)
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    # print the packet number and the protocol name
    print(f"Packet {packet.number}: {protocol}")

# close the capture
capture.close()

# print the total number of packets and the unique protocols
print(f"Total packets: {len(protocols)}")
print(f"Unique protocols: {set(protocols)}")

# print the protocol counts for each protocol
for protocol, count in protocol_counts.items():
    print(f"{protocol}: {count}")
