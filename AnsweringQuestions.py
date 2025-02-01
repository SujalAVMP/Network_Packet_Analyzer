#this program is for finding answers to the pcap-specific questions given in the assignment.
from scapy.all import PcapReader, IP, TCP, UDP, Raw
import sys


input_pcap = r"C:\Users\jiyad\OneDrive\Desktop\IITGN\Computer Networks\Assignment 1\0.pcap" #can also be done on captured_packets.pcap
ims_server_ip = "10.0.137.79" #found using nslookup command on the terminal


unique_connections = set()
total_ims_connections = []
course_registrations = []
total_data_port_4321 = 0
superuser_count = 0


def process_pcap(file):
    global total_data_port_4321, superuser_count
    try:
        with PcapReader(file) as packets: 
            for packet in packets:
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"
                    dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else "N/A"
                    size = len(packet)
                    
                    #connections can be both sent and received on the ims server, so we consider both source and destination ip addresses of the current packet
                    if (dst_ip == ims_server_ip) | (src_ip == ims_server_ip):
                        unique_connections.add((src_ip, src_port))
                        total_ims_connections.append(src_ip)
                    
                    #checking the packet content (payload)
                    payload = ""
                    if packet.haslayer(Raw):
                            payload = bytes(packet[Raw].load).decode(errors="ignore")
                        except Exception as e:
                            print(f"Payload decoding error: {e}")
                    
                    if "course" in payload.lower():
                        course_registrations.append(payload)
                    
                    #total data transmitted over port 4321 - both incoming and outgoing:
                    if src_port == 4321 or dst_port == 4321:
                        total_data_port_4321 += size
                    
                    #for superuser count
                    if "superuser" in payload.lower():
                        superuser_count += 1

    except Exception as e:
        print(f"Error processing pcap file: {e}")
        sys.exit(1)


print(f"Processing {input_pcap} efficiently...")
process_pcap(input_pcap)


print("\nPCAP Analysis Results")
print("Total IMS connections: ", len(total_ims_connections))
print(f"Q1: Unique connections made to the IMS server ({ims_server_ip}): {len(unique_connections)}")
print(f"Q2: Course registrations found: {course_registrations if course_registrations else 'No course registration detected'}")
print(f"Q3: Total data transferred over port 4321: {total_data_port_4321} bytes")
print(f"Q4: Number of SuperUsers detected: {superuser_count}")
