from scapy.all import *

def spoof(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("Got Packet!")
        print("Source: ", pkt[IP].src)
        print("Destination:", pkt[IP].dst)
        a = IP()
        a.src = pkt[IP].dst
        a.dst=pkt[IP].src
        a.ihl=pkt[IP].ihl
        b = ICMP()
        b.type=0
        b.seq=pkt[ICMP].seq
        b.id=pkt[ICMP].id
        if pkt.haslayer(Raw):
           data = pkt[Raw].load
           packet = a/b/data
        else:
            packet = a/b
        print("Spoof reply")
        send(packet, verbose=0)

print("Sniffing....")
pkt = sniff(iface=['lo','enp0s3','docker0','br-6fdd0758cf02'],filter='icmp or arp', prn=spoof)
