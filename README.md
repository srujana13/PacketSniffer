# Packet Sniffer
A simple packet sniffer in python to categorize packets based on protocols. 

This project sniffs of all the packets that are received on the raw socket and parsing of headers for ethernet, IP, TCP, UDP, ICMP, HTTP, HTTPS, QUIC and DNS protocols. 

It records the count of packets received in 30 seconds and generates a csv file with the counts and the respective protocol tabulated. 

## Learning Objectives: 
The project helped me learn how to parse the headers of each packet from link layer protocols to network to transport and to identify the application layer protocols as well. 

We ran a few experiments to analyze the packet count by performing the following activities:

### Exp 1: 
In this experiment, we first play a YouTube video at highest resolution possible in a browser. Once video starts playing, we run the tool. Once the tool exits itself after 30 seconds, we will get an output .csv file.

### Exp 2: 
In this experiment, first run the tool. Then open a browser, go to YouTube website and quickly click on any video. Let this video play until the tool exits. Once the tool exits itself after 30 seconds, we will get an output .csv file.

### Exp 3: 
In this experiment, run the tool. Then open a browser and randomly search stuff on google and open different websites until the tool exits. Once the tool exits itself after 30 seconds, we will get an output .csv file.

We compared the packet count of all three experiments and tabulated the results in a pdf report as shown above. 

## Running Instructions:

1. Run only on Ubuntu systems with sudo access for raw sockets 
2. Run the following: 

''' sudo python3 sniffer_srachak.py '''

3. Notice that a sniffer_srachak.csv is generated 
4. vi sniffer_srachak.csv for results. 
