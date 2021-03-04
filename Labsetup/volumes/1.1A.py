#!/usr/bin/python3
from scapy.all import *
print("sniffing...")
def print_pkt(pkt):
    pkt.show()
pkt = sniff(filter='icmp',prn=print_pkt)

#to run
#sudo chmod a+x 1.1A.py
#sudo python3 1.1A.py