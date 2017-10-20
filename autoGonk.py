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
    mask = None
    gateway = None

    def __init__(self, ip='0', mac='0', mask='0', gw='0'):
        if not self.setIP(ip) or not self.setMAC(mac) or not self.setMask(mask) or not self.setGateway(gw):
            raise ValueError

    def setIP(self, ip='0.0.0.0'):
        self.ip = ip
        return True

    def setMAC(self, mac='00:00:00:00:00:00'):
        self.mac = mac
        return True

    def setMask(self, netmask='255.255.255.255'):
        self.mask = netmask
        return True

    def setGateway(self, gw='127.0.0.1'):
        self.gateway = gw
        return True

    def __repr__(self):
        return "%s/%s (%s) -> %s" % (self.ip, self.mask, self.mac, self.gateway)


class Gateway(Host):
    pass


class Victim(Host):
    pass


if __name__ == "__main__":
    # TODO: this will eventually use a live capture, which will require root...
    gw = Host()
    vic = Host()

    if getuid() > ROOTUID:
        print "[E] must be root!"
        sys.exit(2)

    # TODO: when this switches to a live capture, make sure it ONLY captures on
    # the interface our victim is plugged in to.
    capfile = '/Users/sodaphish/Desktop/sample.pcap'
    a = rdpcap(capfile)
    sessions = a.sessions()

    for session in sessions:
        for pkt in sessions[session]:
            try:
                # pkt[ARP].psrc will have the IP of the target/victim and
                # pkt[ARP].hwsrc will have the target/victim's MAC address
                # print pkt[ARP].hwsrc, pkt[ARP].hwdst, pkt[ARP].psrc,
                # pkt[ARP].pdst
                # we can use any arp packet because we're only going to cap on
                # the interface the client is connected to.
                if pkt[ARP].op == 2:
                    # TODO create a dictionary of potential VICTIM IP's and
                    # MAC's and pick the one with the most hits on it.
                    vic.ip = pkt[ARP].pdst
                    vic.mac = pkt[ARP].hwdst
                    gw.ip = pkt[ARP].psrc
                    gw.mac = pkt[ARP].hwsrc

            except:
                # only concerned with arp packets.
                pass

    vic.gateway = gw.ip

    print vic
    print gw


'''
            try:
                # the TTL threshold will be important.  we'll also want to
                # combine it with knowledge gained about the target/victim.
                if int(pkt[IP].ttl) < 38:
                    pass
                    # print pkt[Ether].src, pkt[Ether].dst, int(pkt[IP].ttl)
            except:
                pass
'''

# __EOF__
