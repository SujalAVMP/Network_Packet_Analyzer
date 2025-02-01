from scapy.all import sniff, wrpcap
import argparse
import signal
import sys

packet_count = 0 

class PacketCapture:
    def _init_(self, interface="lo", output_file="captured_packets.pcap"):
        """
        Initialize the packet capture system.
        
        Args:
            interface (str): Network interface to capture from (default: lo for loopback)
            output_file (str): Name of the PCAP file to save captured packets
        """
        self.interface = interface
        self.output_file = output_file
        self.packets = []  # List to store captured packets
        self.is_running = False
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        
    def packet_callback(self, packet):
        global packet_count
        """
        Callback function called for each captured packet.
        Simply stores the packet in our packet list.
        
        Args:
            packet: Scapy packet object
        """
        self.packets.append(packet)
        packet_count += 1
        # print("The packet is", packet, "and the protocol is", packet)
        print(packet)
        # Print a dot for each packet to show activity
        # sys.stdout.write('.')
        # sys.stdout.flush()
        
    def start_capture(self, filter_str=""):
        """
        Start capturing packets on the specified interface.
        The capture will run until interrupted with Ctrl+C.
        """
        print(f"Starting packet capture on interface {self.interface}")
        print("Press Ctrl+C to stop capturing and save to PCAP file")
        self.is_running = True
        
        try:
            # Start the packet capture
            # store=0 means don't store packets in memory (we handle that ourselves)
            # prn is the callback function called for each packet
            if filter_str != "":
                sniff(iface=self.interface,
                    store=0,
                    prn=self.packet_callback,
                    filter=filter_str)
            else:
                sniff(iface=self.interface,
                      store=0,
                      prn=self.packet_callback)
                  
        except Exception as e:
            print(f"\nError during capture: {e}")
            self.save_packets()
            
    def save_packets(self):
        """
        Save captured packets to the PCAP file.
        """
        if self.packets:
            print(f"\nSaving {packet_count} packets to {self.output_file}")
            wrpcap(self.output_file, self.packets)
            print("Packets saved successfully")
        else:
            print("\nNo packets captured")
            
    def handle_shutdown(self, signum, frame):
        """
        Handle Ctrl+C gracefully by saving captured packets before exiting.
        """
        print("\nStopping capture...")
        self.is_running = False
        self.save_packets()
        sys.exit(0)

def main():
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Capture network packets to PCAP file')
    parser.add_argument('-i', '--interface', default='lo',
                      help='Network interface to capture from (default: lo)')
    parser.add_argument('-o', '--output', default='captured_packets.pcap',
                      help='Output PCAP file (default: captured_packets.pcap)')
    
    args = parser.parse_args()
    
    # Create and start the packet capturer
    capturer = PacketCapture(interface=args.interface, output_file=args.output)
    filter_str = "not arp and not icmp6 and not (udp port 67 or udp port 68 or udp port 5353)"
    # filter_str = ""
    capturer.start_capture(filter_str)

if __name__ == "_main_":
    main()