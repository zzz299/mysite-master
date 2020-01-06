from scapy.all import *
def icmp(pcap):
    icmpv6 = dict()
    #解析RS报文
    if pcap.haslayer("ICMPv6ND_RS"):
        icmpv6["type"]=pcap["ICMPv6ND_RS"].type
        icmpv6["code"]=pcap["ICMPv6ND_RS"].code
        icmpv6["cksum"]=pcap["ICMPv6ND_RS"].cksum
        icmpv6["res"]=pcap["ICMPv6ND_RS"].res
    elif pcap.haslayer("ICMPv6ND_RA"):
        icmpv6["type"]=pcap["ICMPv6ND_RA"].type
        icmpv6["code"] = pcap["ICMPv6ND_RA"].code
        icmpv6["cksum"] = pcap["ICMPv6ND_RA"].cksum
        icmpv6["M"] = pcap["ICMPv6ND_RA"].M
        icmpv6["O"] = pcap["ICMPv6ND_RA"].O
        icmpv6["H"] = pcap["ICMPv6ND_RA"].H
        icmpv6["Pref"] = pcap["ICMPv6ND_RA"].prf
        icmpv6["P"] = pcap["ICMPv6ND_RA"].P
        icmpv6["res"] = pcap["ICMPv6ND_RA"].res
        icmpv6["routerlifetime"] = pcap["ICMPv6ND_RA"].routerlifetime
        icmpv6["reachabletime"] = pcap["ICMPv6ND_RA"].reachabletime
        icmpv6["retranstimer"] = pcap["ICMPv6ND_RA"].retranstimer

def judge(pcap):
    if pcap.haslayer("IPv6"):
        ipv6 = dict()
        ipv6["version"] = pcap["IPv6"].version
        ipv6["Traffic Classes"] = pcap["IPv6"].tc
        ipv6["Flow Label"] = pcap["IPv6"].fl
        ipv6["Payload Length"] = pcap["IPv6"].plen
        ipv6["Next Header"] = pcap["IPv6"].nh
        ipv6["Hop Limit"] = pcap["IPv6"].hlim
        ipv6["src"] = pcap["IPv6"].src
        ipv6["dst"] = pcap["IPv6"].dst
        #解析逐跳报文
        if ipv6["Next Header"]==0:
            HopByHop = dict()
            HopByHop["Next Length"] = pcap["IPv6ExtHdrHopByHop"].nh
            HopByHop["len"] = pcap["IPv6ExtHdrHopByHop"].len
            HopByHop["options"] = pcap["IPv6ExtHdrHopByHop"].options
