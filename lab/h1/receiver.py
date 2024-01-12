#!/usr/bin/env python
import sys
import os
from scapy.all import sniff, get_if_list, Ether, get_if_hwaddr, IP, Raw

def filter_funtion(my_mac):
    my_mac = my_mac
    def _isNotOutgoing(pkt):
        return pkt[Ether].src != my_mac
    return _isNotOutgoing

def handle_pkt(pkt):
    print("Got a Packet ! ! !")
    pkt.show()

def main():
    iface = "eth0"
    MAC_address = "00:00:00:00:00:11"
    print("sniffing on interface %s" % iface)
    sys.stdout.flush()

    my_filter = filter_funtion(MAC_address)

    sniff(filter="ip", iface = iface,
          prn = lambda x: handle_pkt(x), lfilter=my_filter)

if __name__ == '__main__':
    main()
