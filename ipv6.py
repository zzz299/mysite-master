from scapy.all import *

type1={6:"TCP",58:"icmpv6",134:"RA",44:"fragment",0:"HopByHop",136:"NA",135:"NS",133:"RS",59:"No Next Header",17:"UDP"}
def icmp(pcap):
    icmpv6 = dict()
    #解析RS报文
    if pcap.haslayer("ICMPv6ND_RS"):
        icmpv6["type"]=type1[pcap["ICMPv6ND_RS"].type]
        icmpv6["code"]=pcap["ICMPv6ND_RS"].code
        icmpv6["cksum"]=hex(pcap["ICMPv6ND_RS"].cksum)
        icmpv6["res"]=pcap["ICMPv6ND_RS"].res
        icmpv6["optiontype"]=pcap["ICMPv6NDOptSrcLLAddr"].type
        icmpv6["optionlen"]=pcap["ICMPv6NDOptSrcLLAddr"].len
        icmpv6["lladdr"] = pcap["ICMPv6NDOptSrcLLAddr"].lladdr
    #解析RA报文
    elif pcap.haslayer("ICMPv6ND_RA"):
        icmpv6["type"]=type1[pcap["ICMPv6ND_RA"].type]
        icmpv6["code"] = pcap["ICMPv6ND_RA"].code
        icmpv6["cksum"] = hex(pcap["ICMPv6ND_RA"].cksum)
        icmpv6["M"] = pcap["ICMPv6ND_RA"].M
        icmpv6["O"] = pcap["ICMPv6ND_RA"].O
        icmpv6["H"] = pcap["ICMPv6ND_RA"].H
        icmpv6["Pref"] = pcap["ICMPv6ND_RA"].prf
        icmpv6["P"] = pcap["ICMPv6ND_RA"].P
        icmpv6["res"] = pcap["ICMPv6ND_RA"].res
        icmpv6["routerlifetime"] = pcap["ICMPv6ND_RA"].routerlifetime
        icmpv6["reachabletime"] = pcap["ICMPv6ND_RA"].reachabletime
        icmpv6["retranstimer"] = pcap["ICMPv6ND_RA"].retranstimer
        icmpv6["optiontype"] = pcap["ICMPv6NDOptSrcLLAddr"].type
        icmpv6["optionlen"] = pcap["ICMPv6NDOptSrcLLAddr"].len
        icmpv6["lladdr"] = pcap["ICMPv6NDOptSrcLLAddr"].lladdr
    #解析NS报文
    elif pcap.haslayer("ICMPv6ND_NS"):
        icmpv6["type"]=type1[pcap["ICMPv6ND_NS"].type]
        icmpv6["code"]=pcap["ICMPv6ND_NS"].code
        icmpv6["cksum"]=hex(pcap["ICMPv6ND_NS"].cksum)
        icmpv6["res"]=pcap["ICMPv6ND_NS"].res
        icmpv6["tgt"]=pcap["ICMPv6ND_NS"].tgt
        try:
            icmpv6["optiontype"] = pcap["ICMPv6NDOptSrcLLAddr"].type
            icmpv6["optionlen"] = pcap["ICMPv6NDOptSrcLLAddr"].len
            icmpv6["lladdr"]=pcap["ICMPv6NDOptSrcLLAddr"].lladdr
        except:
            icmpv6["optiontype"] = " "
            icmpv6["optionlen"] = " "
            icmpv6["lladdr"] = " "
    #解析NA报文
    elif pcap.haslayer("ICMPv6ND_NA"):
        icmpv6["type"] = type1[pcap["ICMPv6ND_NA"].type]
        icmpv6["code"] = pcap["ICMPv6ND_NA"].code
        icmpv6["cksum"] = hex(pcap["ICMPv6ND_NA"].cksum)
        icmpv6["res"] = pcap["ICMPv6ND_NA"].res
        icmpv6["R"] = pcap["ICMPv6ND_NA"].R
        icmpv6["S"] = pcap["ICMPv6ND_NA"].S
        icmpv6["O"] = pcap["ICMPv6ND_NA"].O
        icmpv6["tgt"] = pcap["ICMPv6ND_NA"].tgt
        try:
            icmpv6["optiontype"] = pcap["ICMPv6NDOptDstLLAddr"].type
            icmpv6["optionlen"] = pcap["ICMPv6NDOptDstLLAddr"].len
            icmpv6["lladdr"] = pcap["ICMPv6NDOptDstLLAddr"].lladdr
        except:
            icmpv6["optiontype"] = " "
            icmpv6["optionlen"] = " "
            icmpv6["lladdr"] = " "
    else:
        icmpv6["type"]="no"
    return icmpv6
def judge(pcap):
    if pcap.haslayer("IPv6"):
        ipv6 = dict()
        ipv6["version"] = pcap["IPv6"].version
        ipv6["Traffic Classes"] = pcap["IPv6"].tc
        ipv6["Flow Label"] = pcap["IPv6"].fl
        ipv6["Payload Length"] = pcap["IPv6"].plen
        ipv6["Next Header"] = type1[pcap["IPv6"].nh]
        ipv6["Hop Limit"] = pcap["IPv6"].hlim
        ipv6["src"] = pcap["IPv6"].src
        ipv6["dst"] = pcap["IPv6"].dst
        print("ipv6",ipv6)
        #解析逐跳报文
        if pcap["IPv6"].nh==0:
            HopByHop = dict()
            HopByHop["Next Header"] = type1[pcap["IPv6ExtHdrHopByHop"].nh]
            HopByHop["len"] = pcap["IPv6ExtHdrHopByHop"].len
            HopByHop["options"] = pcap["IPv6ExtHdrHopByHop"].options
            print("HopByHop",HopByHop)
            if pcap["IPv6ExtHdrHopByHop"].nh==58:
                icmpv6 = icmp(pcap)
                print("icmpv6",icmpv6)
        #解析分片报文
        elif pcap["IPv6"].nh==44:
            fragment=dict()
            fragment["Next Header"]=type1[pcap["IPv6ExtHdrFragment"].nh]
            fragment["res1"] = pcap["IPv6ExtHdrFragment"].res1
            fragment["offset"] = pcap["IPv6ExtHdrFragment"].offset
            fragment["res2"] = pcap["IPv6ExtHdrFragment"].res2
            fragment["m"] = pcap["IPv6ExtHdrFragment"].m
            fragment["id"] = pcap["IPv6ExtHdrFragment"].id
            print("fragment",fragment)
            if pcap["IPv6ExtHdrFragment"].nh==58:
                icmpv6 = icmp(pcap)
                print("icmpv6",icmpv6)
        #解析icmpv6报文
        elif pcap["IPv6"].nh==58:
            icmpv6=icmp(pcap)
            print("icmpv6", icmpv6)
while(True):
    pcap=sniff(iface="eth0",count=10)
    for p in pcap:
        if p.haslayer("IPv6"):
            judge(p)