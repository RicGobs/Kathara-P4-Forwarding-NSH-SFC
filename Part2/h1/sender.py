#!/usr/bin/env python
import sys
import socket
from scapy.all import sendp, get_if_hwaddr
from scapy.all import Ether, IP


def main():

    if len(sys.argv)<3:
        print('2 arguments required: <IP address> "<message>"')
        exit(1)

    # takes destination IP address
    dest_IP_address = socket.gethostbyname(sys.argv[1])

    # takes message to send
    message = sys.argv[2]

    # takes interface, in this project it is always this for h1
    iface = "eth0"

    # takes destination_MAC_address, in this project it is always this for h1
    destination_MAC_address = "00:00:00:00:00:22"

    # creates an Ethernet packet with an IP layer and a payload using Scapy
    pkt =  Ether(src=get_if_hwaddr(iface), dst=destination_MAC_address)
    pkt = pkt / IP(dst=dest_IP_address, tos=0) / message

    # tos=0 means no specific type of service or priority is requested for the packet

    # Send the packet using Scapy
    sendp(pkt, iface=iface, verbose=False)

    print("Packet sent on interface %s to %s with message <%s>" % (iface, str(dest_IP_address),message))


if __name__ == '__main__':
    main()
