import numpy as np
import pyshark
from collections import defaultdict
import matplotlib.pyplot as plt
from tqdm import tqdm


class PacketsAnalyzer:
    def __init__(self):
        # Define protocol numbers
        self.IP_PROTOCOL = 0x0800  
        self.UDP_PROTOCOL = 17     
        self.TCP_PROTOCOL = 6    
        
        # Dictionary to store packet statistics
        self.stats = {
            'total_bytes': 0,
            'total_packets': 0,
            'min_size': float('inf'),
            'max_size': 0,
            'packet_sizes': [],
            'source_dest_pairs': set(),
            'source_flows': defaultdict(int),
            'dest_flows': defaultdict(int),
            'data_transfer': defaultdict(int),  # (src, dst) -> bytes
            'protocol_counts': defaultdict(int)
            }
        
        
    def process_pcap(self, pcap_file):
        """Process a PCAP file and gather statistics"""
        packets = pyshark.FileCapture(pcap_file, keep_packets=False)
        
        for i in tqdm(packets):
        # for i in tqdm(range(100000)):
            packet = packets.next()
            # Extract packet size
            packet_size = int(packet.length)
            self.stats['total_bytes'] += packet_size
            self.stats['total_packets'] += 1
            self.stats['min_size'] = min(self.stats['min_size'], packet_size)
            self.stats['max_size'] = max(self.stats['max_size'], packet_size)
            self.stats['packet_sizes'].append(packet_size)
            
            # Process IP layer if present
            if 'IP' in packet:
                ip_pkt = packet['IP']
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                self.stats['protocol_counts'][ip_pkt.proto] += 1
                
                # Get ports if TCP/UDP
                if 'TCP' in packet:
                    tcp_pkt = packet['TCP']
                    src_port = packet['TCP'].srcport
                    dst_port = packet['TCP'].dstport
                    protocol = 'TCP'
                elif 'UDP' in packet:
                    udp_pkt = packet['UDP']
                    src_port = packet['UDP'].srcport
                    dst_port = packet['UDP'].dstport
                    protocol = 'UDP'
                else:
                    continue
                
                # Create source:port and destination:port pairs
                src_dst_pair = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                self.stats['source_dest_pairs'].add(src_dst_pair)
                
                # Count flows
                self.stats['source_flows'][src_ip] += 1
                self.stats['dest_flows'][dst_ip] += 1
                
                # Track data transfer
                self.stats['data_transfer'][src_dst_pair] += packet_size
                
                
    def process_packet(self, packet):
        """Process a single packet and update statistics"""
        packet_size = int(packet.length)
        
        self.stats['total_bytes'] += packet_size
        self.stats['total_packets'] += 1
        self.stats['min_size'] = min(self.stats['min_size'], packet_size)
        self.stats['max_size'] = max(self.stats['max_size'], packet_size)
        self.stats['packet_sizes'].append(packet_size)
        
        # Process IP layer if present
        if "IP" in packet:
            ip_pkt = packet["IP"]
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            self.stats['protocol_counts'][ip_pkt.proto] += 1
            
            # Get ports if TCP/UDP
            if "TCP" in packet:
                tcp_pkt = packet["TCP"]
                src_port = packet["TCP"].srcport
                dst_port = packet["TCP"].dstport
                protocol = 'TCP'
            elif "UDP" in packet:
                udp_pkt = packet["UDP"]
                src_port = packet["UDP"].srcport
                dst_port = packet["UDP"].dstport
                protocol = 'UDP'
            else:
                return
            
            # Create source:port and destination:port pairs
            src_dst_pair = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            self.stats['source_dest_pairs'].add(src_dst_pair)
            
            # Count flows
            self.stats['source_flows'][src_ip] += 1
            self.stats['dest_flows'][dst_ip] += 1
            
            # Track data transfer
            self.stats['data_transfer'][src_dst_pair] += packet_size
    
    def write_stats(self, filename="packet_statistics.txt"):
        """Write statistics to a file"""
        with open(filename, 'w') as f:
            f.write("=== Basic Statistics ===\n")
            f.write(f"Total packets: {self.stats['total_packets']}\n")
            f.write(f"Total bytes: {self.stats['total_packets']}\n")
            f.write(f"Minimum packet size: {self.stats['min_size']}\n")
            f.write(f"Maximum packet size: {self.stats['max_size']}\n\n")
            
            f.write("=== Protocol Counts ===\n")
            for proto, count in self.stats['protocol_counts'].items():
                f.write(f"{proto}: {count}\n")
            f.write("\n")
            
            f.write("=== Source/Destination Pairs ===\n")
            for pair in self.stats['source_dest_pairs']:
                f.write(f"{pair}\n")
            f.write("\n")
            
            f.write("=== Source Flows ===\n")
            for ip, count in self.stats['source_flows'].items():
                f.write(f"{ip}: {count}\n")
            f.write("\n")
            
            f.write("=== Destination Flows ===\n")
            for ip, count in self.stats['dest_flows'].items():
                f.write(f"{ip}: {count}\n")
            f.write("\n")
            
            f.write("=== Data Transfer ===\n")
            for pair, bytes in self.stats['data_transfer'].items():
                f.write(f"{pair}: {bytes} bytes\n")
                                       
            print(f"Statistics have been written to {filename}")
                           
    def display_stats(self):
        """Display packet statistics"""
        print("Total packets:", self.stats['total_packets'])
        print("Total bytes:", self.stats['total_bytes'])
        print("Minimum packet size:", self.stats['min_size'])
        print("Maximum packet size:", self.stats['max_size'])
        
        # Display protocol counts
        print("\nProtocol counts:")
        for proto, count in self.stats['protocol_counts'].items():
            print(f"{proto}: {count}")
        
        # Display source/destination pairs
        print("\nSource/Destination pairs:")
        for pair in self.stats['source_dest_pairs']:
            print(pair)
        
        # Display source flows
        print("\nSource flows:")
        for ip, count in self.stats['source_flows'].items():
            print(f"{ip}: {count}")
        
        # Display destination flows
        print("\nDestination flows:")
        for ip, count in self.stats['dest_flows'].items():
            print(f"{ip}: {count}")
        
        # Display data transfer
        print("\nData transfer:")
        for pair, bytes in self.stats['data_transfer'].items():
            print(f"{pair}: {bytes} bytes")
            
    def plot_packet_sizes(self):
        """Plot a histogram of packet sizes"""
        plt.hist(self.stats['packet_sizes'], bins=50, color='blue', edgecolor='black')
        plt.title("Packet Size Distribution")
        plt.xlabel("Packet Size (bytes)")
        plt.ylabel("Frequency")
        plt.show()
        
# Example usage
sniffer = PacketsAnalyzer()
sniffer.process_pcap('0.pcap')
# sniffer.display_stats()
sniffer.write_stats()

# Plot packet size distribution
sniffer.plot_packet_sizes()