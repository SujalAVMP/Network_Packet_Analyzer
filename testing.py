import pyshark

packets = pyshark.FileCapture('0.pcap', keep_packets=True)

packet = packets[0]

print(dir(packet))
print("Packet length:", packet.length)
print("THIS IS WHAT IM LOOKING FOR", dir(packet.ip.src))
packet.ip.pretty_print()
packet.tcp.pretty_print()
print("THIS IS MY TCP THINGY", packet.tcp.dstport)
print(dir(packet.tcp))