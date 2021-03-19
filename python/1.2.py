from scapy.all import *

a = IP() 
a.dst = '10.0.2.15' #another machine in our network. we will run wireshark on this machine to capture the spoofed packet.
a.src = '105.105.105.105' #fake ip
b = ICMP()
p = a/b
send(p)
