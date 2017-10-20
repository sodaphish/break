"""
autoGonk -- auto-configuration script for break

Step 0: be vewy quiet, wew hunting wabbits! (silence on the wire)
Step 1: calculate victim IP and MAC address 
Step 2: calculate gateway IP and MAC
Step 3: ?
Step 4: write our configuration to file
"""

import sys
from os import getuid

try:
    from scapy.all import *
except ImportError as e:
    print("[E] %s" % e)
    sys.exit(2)


class MACAddress():
    oui = "00:00:00"
    machine = "00:00:00"
    
    def __init__(self):
        pass

class Victim():
    def __init__(self,ip='0.0.0.0',mac='00:00:00:00:00:00'):
        pass
    
    def setIP(self,ip='0.0.0.0'):
        #validate IP -- don't allow RFC 3927 169.254/16 
        pass
    
    def setMAC(self,mac='00:00:00:00:00:00'):
        #validate MAC address, confirm its in the OUI database
        pass
    
    def __repr__(self):
        pass
    
    
    
class Gateway():
    
    def __init__(self,ip='0.0.0.0',mac='00:00:00:00:00:00'):
        pass
    
    def setIP(self,ip='0.0.0.0'):
        pass
    
    def setMAC(self,mac='00:00:00:00:00:00'):
        pass
    
    def __repr__(self):
        pass



if __name__ == "__main__":
    # TODO: this will eventually use a live capture, which will require root...
    
    if getuid() > 0:
        print "[E] must be root!"
        sys.exit(2)
        
    capfile = '/home/sodaphish/Desktop/sample.pcap'
    a = rdpcap(capfile)
    sessions = a.sessions()

    for session in sessions:
        for pkt in sessions[session]:
            try:
                # pkt[ARP].psrc will have the IP of the target/victim and 
                # pkt[ARP].hwsrc will have the target/victim's MAC address
                #print pkt[ARP].hwsrc, pkt[ARP].hwdst, pkt[ARP].psrc, pkt[ARP].pdst
                pass
            except:
                #only concerned with arp packets.
                pass
            
            try:
                # the TTL threshold will be important.  we'll also want to 
                # combine it with knowlege gained about the target/victim.
                if int(pkt[IP].ttl) < 38:
                    print pkt[Ether].src, pkt[Ether].dst, int(pkt[IP].ttl)
            except:
                pass
            






            
            