# Packet sniffer in python
# Srujana Rachakonda
# srachak - 200316008

import socket
from struct import *
import time
import csv

ETHERNET_PACKET = 0x003
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETHERNET_PACKET))
# Setting the timer for the program to run for 30 seconds
timeout = time.time() + 30
# Dictionary which keeps track of all the protocol counts
count_dictionary = {'ip': 0, 'tcp': 0, 'udp': 0, 'dns': 0, 'icmp': 0, 'http': 0, 'https': 0, 'quic': 0}

# receiving packets
while True:

    time.sleep(1)
    if time.time() > timeout:
        break
    packet = s.recvfrom(65565)
    packet = packet[0]

    # Extracting the ethernet header
    # Ethernet headers have a max size of 14
    eth_length = 14
    eth_header = packet[:eth_length]
    # unpacking the header
    eth = unpack('!6s6sH', eth_header)
    # Ethernet type / protocol identified after source mac address
    # (first 6 bytes), destination mac address (next 6 bytes)
    eth_protocol = socket.ntohs(eth[2])

    # ipv4 packets are identified as ethernet protocol 0x0800
    if eth_protocol == 8:
        # incrementing counts for ip packets
        count_dictionary['ip'] = count_dictionary['ip'] + 1

        # extracting IP headers from the reamining packetself.
        # IP headers vary from 20 - 60 bytes. Minimum size = 20 therefore, we extract 20 bytes
        ip_header = packet[eth_length:20 + eth_length]
        # unpacking IP header
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        # According to the packet format, first byte is version and ip header length
        version = (iph[0] >> 4) & 0xf
        ip_header_length = (iph[0] & 0xf) * 4
        # Protocol is the 10th byte and sixth item in our unpacked structure
        protocol = iph[6]
        # if protocol number is 6, we identify it as a TCP  transport layer packet
        if protocol == 6:
            # Incrementing TCP protocol count
            count_dictionary['tcp'] = count_dictionary['tcp'] + 1
            # Getting the starting point of TCP header
            t = ip_header_length + eth_length
            # Extracting TCP header
            tcp_header = packet[t:t + 20]
            # Unpacking TCP header
            tcph = unpack('!HHLLBBHHH', tcp_header)
            # Fetching source and destination ports
            source_port = tcph[0]
            destination_port = tcph[1]
            # Finding http packets using port number 80
            if source_port == 80 or destination_port == 80:
                count_dictionary['http'] = count_dictionary['http'] + 1
                # finding https packets using port number 443
            if source_port == 443 or destination_port == 443:
                count_dictionary['https'] = count_dictionary['https'] + 1
        # ICMP packets use protocol value 1, can be reproduced using ping statements
        if protocol == 1:
            count_dictionary['icmp'] = count_dictionary['icmp'] + 1
        # Protocol number 17 corresponds to udp packets
        if protocol == 17:

            count_dictionary['udp'] = count_dictionary['udp'] + 1
            # Getting starting point of udp header
            u = ip_header_length + eth_length
            udph_length = 8
            # Extracting udp header
            udp_header = packet[u:u + 8]
            # Unpacking udp header
            udph = unpack('!HHHH', udp_header)
            # Fetching source and destination ports
            source_port = udph[0]
            destination_port = udph[1]
            # Identifying dns using port 53
            if source_port == 53 or destination_port == 53:
                count_dictionary['dns'] = count_dictionary['dns'] + 1
            # Finding potential quic header starting point
            q = u + udph_length
            # Fetching first 13 bytes of potential quip header
            packet_header = packet[q:q + 13]
            # Extracting the header
            potential_quic_header = unpack('!BQBBBB', packet_header)
            # QUIC headers start with a Q
            if potential_quic_header[2] == 'Q':
                # Incrementing quic count
                count_dictionary['quic'] = count_dictionary['quic'] + 1
            # Quic is http/https over UDP hence checking the combination of udp and 80 or 443
            if source_port == 80 or source_port == 443 or destination_port == 80 or destination_port == 443:
                count_dictionary['quic'] = count_dictionary['quic'] + 1

print(count_dictionary)

# writing to a csv file

count_file = open("sniffer_srachak.csv", "w")
writer = csv.writer(count_file)
writer.writerow(["protocol", "count"])
for key, value in count_dictionary.items():
    writer.writerow([key, value])
count_file.close()
