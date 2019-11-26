#!/usr/bin/python3

# sudo iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1

from scapy.all import *
from netfilterqueue import NetfilterQueue

def ml(frame_len, ip_flag, ip_len, qname, qname_len):
    print(frame_len, ip_flag, ip_len, qname, qname_len)
    return True

def decision(packet):
    payload = IP(packet.get_payload())

    if not payload.haslayer(DNSQR):
        # Not a dns query, accept and go on
        return False
    else:
        print("Payload summary: {}".format(payload.summary()))
        #payload.show()
        #frame_len = packet.get_payload_len()
        #frame_len = len(payload)
        ip_flag = ("DF" in payload.flags)
        ip_len = payload.len
        frame_len = ip_len + 14
        qname = payload[DNS].qd.qname

        return ml(frame_len, ip_flag, ip_len, qname.decode("utf-8"), len(qname.decode("utf-8")))

def firewall(packet):
    if decision(packet):
        packet.drop()
    else:
        packet.accept()

queueId = 1

nfqueue = NetfilterQueue()
nfqueue.bind(queueId, firewall)

# wait for packets
try:
    print("Intercepting nfqueue: {}".format(str(queueId)))
    #print("Spoofing {} to {}".format(fqdnToSpoof.decode(), spoofToIP.decode()))
    print("------------------------------------------")
    nfqueue.run()
except KeyboardInterrupt:
    pass
