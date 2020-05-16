# PacketSniffer
A simple packet sniffer in python to categorize packets based on protocols. 

This project sniffs of all the packets that are received on the raw socket and parsing of headers for ethernet, IP, TCP, UDP, ICMP, HTTP, HTTPS, QUIC and DNS protocols. 

It records the count of packets received in 30 seconds and generates a csv file with the counts and the respective protocol tabulated. 

# Learning Objectives: 
The project helped me learn how to parse the headers of each packet from link layer protocols to network to transport and to identify the application layer protocols as well. 

# Running Instructions:

1. Run only on Ubuntu systems with sudo access for raw sockets 
2. Run the following: 

sudo python3 sniffer_srachak.py

3. Notice that a sniffer_srachak.csv is generated 
4. vi sniffer_srachak.csv for results. 
