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
    from netaddr import *
except ImportError as e:
    print("[E] %s" % e)
    sys.exit(2)

ROOTUID = 100000


class Host():
    ip = None
    mac = None
    
    def __init__(self,ip,mac):
        try:
            if not self.setIP(ip) or not self.setMAC(mac):
                raise ValueError
        except:
            raise ValueError
    
    def setIP(self,ip='0.0.0.0'):
        try:
            self.ip = IPAddress(ip,4,0)
        except Exception as e:
            raise e
        
        if self.ip.is_ipv4_compat() and not self.ip.is_loopback():
            return True
        
        return False
    
    def setMAC(self,mac='00:00:00:00:00:00'):
        try:
            self.mac = EUI(mac)
        except Exception as e:
            raise e
       
        if type(self.mac) in 'netaddr.eui.EUI':
            return True
        
        return False
    
    def __repr__(self):
        pass
    
    
    
class Gateway(Host):
    continue

class Victim(Host):
    continue



if __name__ == "__main__":
    # TODO: this will eventually use a live capture, which will require root...
    
    if getuid() > ROOTUID:
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
            






            
            