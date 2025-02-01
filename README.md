# Packet Sniffer and PCAP Analyzer

Download the sample PCAP file from here: [PCAP Files](https://drive.google.com/drive/u/4/folders/1n84jGddZ38fDjy9jKH3qw3J_H0SaKThu)

Turn off your wifi, run the adhoc_network_create.sh file on Ubuntu 24.04 after substituting wlp0s20f3 with your wireless network interface to create an adhoc network. Connect to the network using some other Windows or Mac machine. 

In a terminal with elevated privileges (administrator or sudo), run 
```bash 
sudo python packet_capture.py --interface <INSERT INTERFACE NAME>
``` 
on that machine to capture the packets and run the following command to send the packets over the adhoc network from the Ubuntu Machine

```bash
sudo tcpreplay-edit --enet-dmac=FF:FF:FF:FF:FF:FF --mbps=1 --stats=1 -i <YOUR NETWORK INTERFACE> <PCAP FILE>
```