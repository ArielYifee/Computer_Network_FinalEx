#!/usr/bin/python
from scapy.all import *
print("sniffing...")
def print_pkt(pkt):
	pkt.show()

#pkt = sniff(filter='icmp',prn=print_pkt)
#pkt = sniff(filter='tcp and src host 10.0.2.15 and dst port 23', prn=print_pkt)
pkt = sniff(filter="dst net 128.230.0.0/16",prn=print_pkt)
