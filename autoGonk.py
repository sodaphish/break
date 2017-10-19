"""
autoGonk -- testing out auto-determining which interfaces serve which function
"""

import sys
from os import getuid
from threading import Thread
from ipaddress import IPv4Address

try:
    import pcapy
    from scapy.all import *
    from pcapy import findalldevs, open_live, open_offline
    from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
except ImportError as e:
    print("[E] %s" % e)
    sys.exit(1)


from break_config import *


class PacketProcessor(Thread):
    '''
    pre: takes an open pcap device and itterates packets until pre-conditions are met... 
    post: will pre-populate the things we need to pull-off our MiTM regardless of how we're cabled
    '''

    def __init__(self, pcapObj):
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SSL == datalink:
            self.decoder = LinuxSSLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.pcap = pcapObj
        Thread.__init__(self)

    def run(self):
        self.pcap.loop(0, self.packetHandler)

    def packetHandler(self, hdr, data):
        frame = self.decoder.decode(data)


def getInterfaces(datalink=1, fil="eth"):
    '''
    returns a list of devices of the specified datalink type
    see the end of `pydoc pcapy` for a full list of datalink types based on 
    the filter specified.
    '''
    retval = []
    for interface in findalldevs():
        try:
            z = open_live(interface, 1500, 0, 100)
            if z.datalink() == datalink:
                if str(interface).startswith(fil):
                    retval.append(interface)
        except:
            # let the bodies hit the floor!
            pass
    return retval


if __name__ == "__main__":
    '''
    perform unit testing of our classes and functions
    '''
    '''
    print("[I] capturing on %s" % iface)
    iface = getInterfaces(fil="en")[0]
    print("[I] capturing on %s" % iface)
    if getuid() > 0:
        print "[E] you must be root"
        sys.exit(2)

    print("[I] quitting...")
    sys.exit()
    '''

    capfile = '/Users/sodaphish/Desktop/sample.pcapng'
    a = rdpcap(capfile)
    sessions = a.sessions()

    for session in sessions:
        for pkt in sessions[session]:
            try:
                print pkt[ARP], pkt[ARP]
            except:
                pass