from scapy.all import sniff,rdpcap,wrpcap
from IDS.db import *
import multiprocessing
import time
import operator
from .views import analysis_http_attack,analysis

import socket
import ssl
from easygui import *
class server_ssl:
    def bulid_listen(self):
        sock = socket.socket()
        print("建立套接字成功")
        sock.bind(("127.0.0.2", 10002))
        print("绑定成功")
        sock.listen(1)
        text = ""
        while True:
            conn, addr = sock.accept()
            connstream = ssl.wrap_socket(conn, "keyy.pem", "certt.pem", server_side=True)
            try:
                data = connstream.recv(1024).decode("utf-8")
                text = text + "客户端:" + str(data) + "\r\n" + "服务端:"
                msg = enterbox(msg=text, title="服务端")
                text = text + msg + "\r\n"
                msg = msg.encode(encoding="utf-8")
                connstream.send(msg)
            except:
                connstream.close()
                text=""

def analysis_pcap(pcaps):
    PCAPNUMS = len(pcaps)
    con, cur = dbcur()
    query = 'update pcapsnum set num= ' + str(PCAPNUMS) + ' where id=0'
    # print(query)
    cur.execute(query)
    con.commit()
    con.close()
    analysis(pcaps)

def capture_pcap():

    for i in range(300):  # os模块的getpid()可以获得该进程的进程号,os.ppid()可以获得该进程的父进程的进程号
        print("---in %d" % (i))
        pcap = sniff(iface='eth0',timeout=1)
        FILE = 'demo.pcap'

        wrpcap(FILE,pcap)
        try:
            pcaps = rdpcap(FILE)
            q = multiprocessing.Process(target=analysis_pcap,args=(pcaps,))
            q.daemon = True
            q.start()
            p = multiprocessing.Process(target=test_ipv6dos, args=(pcaps,))
            p.daemon = True
            p.start()

        except:
            continue
    print("********\n***************\n**********\n*******\n***\n****\n****\n****\n*****\nfinish")


def test_ipv6dos(pcaps):
    srclist=dict()
    for pcap in pcaps:
        try:
            ptime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(pcap.time)))
            if pcap.haslayer("IPv6"):
                s=pcap['IPv6'].src not in srclist.keys()
                if (s):
                    srclist[pcap['IPv6'].src]=1
                if s==False:
                    b=srclist[pcap['IPv6'].src]
                    srclist[pcap['IPv6'].src]=srclist[pcap['IPv6'].src]+1
        except:
            continue
    sorts= sorted(srclist.items(), key=operator.itemgetter(1), reverse=True)
    count=0
    for key,value in sorts:
        if value > 500:
            con, cur = dbcur()
            query = 'update attack_check set ipv6_dos_src='+str(key)+',ipv6_dos_check='+str(value)+'where id=0'
            cur.execute(query)
            con.commit()
            con.close()
        count=1
        if count==1:
            break

    flood(pcaps)

def flood(pcaps):
    sumnum=len(pcaps)
    countnum=0
    for pcap in pcaps:
        if pcap.haslayer("IPv6"):
            try:
                if pcap.haslayer("ICMPv6ND_RA"):
                    if pcap["IPv6"].dst=="ff02::1" and pcap["ICMPv6ND_RA"].type==134:
                        countnum=countnum+1
                elif pcap.haslayer("ICMPv6ND.NS"):
                    if pcap["IPv6"].dst == "ff02::1" and pcap["ICMPv6ND_NS"].type == 135:
                        countnum=countnum+1
            except:
                continue
    if countnum>((sumnum/3)*2):
        con, cur = dbcur()
        query = 'update attack_check set ipv6_flood_num='+str(countnum)+' where id=0'
        cur.execute(query)
        con.commit()
        con.close()
    else:
        con, cur = dbcur()
        query = 'update attack_check set ipv6_flood_num=0 where id=0'
        cur.execute(query)
        con.commit()
        con.close()


    parasite6(pcaps)


def parasite6(pcaps):
    ndp_table=dict()
    ndpmac_table=dict()
    countnum=0
    ipv6_num = 0
    src = ''
    for pcap in pcaps:
        try:
            if pcap.haslayer("IPv6"):
                src = pcap["IPv6"].src
                ipv6_num+=1
                if pcap["IPv6"].src not in ndp_table.keys():
                    ndp_table[pcap["IPv6"].src]=pcap["Ethernet"].src
                else:
                    if ndp_table[pcap["IPv6"].src]!=pcap["Ethernet"].src:
                        countnum=countnum+1
                if pcap["Ethernet"].src not in ndpmac_table.keys():
                    ndpmac_table[pcap["Ethernet"].src]=pcap["IPv6"].src
                else:
                    if ndpmac_table[pcap["Ethernet"].src]!=pcap["IPv6"].src:
                        countnum=countnum+1
        except:
            continue
    con, cur = dbcur()
    print("[+] ndp_detect:"+str(countnum))
    print("[+] ipv6_num: ", str(ipv6_num))
    if(ipv6_num>1000):
        query = "update attack_check set ipv6_dos_src='"+str(src)+"',ipv6_dos_check=1 where id=0"
        cur.execute(query)
    else:
        query = 'update pcapsnum set num='+str(ipv6_num)+' where id=1'
        cur.execute(query)
        query = "update attack_check set ipv6_dos_check=0 where id=0"
        cur.execute(query)

    query = 'update attack_check set ipv6_ndp_spoofer_check= ' + str(countnum) + ' where id=0'
    cur.execute(query)
    con.commit()
    con.close()
    arppar(pcaps)
def arppar(pcaps):
    countnum=0
    arp_table=dict()
    for p in pcaps:
        try:
            if p.haslayer("ARP"):
                if p["ARP"].psrc not in arp_table.keys():
                    arp_table[p["ARP"].psrc]=p["ARP"].hwsrc
                else:
                    if arp_table[p["ARP"].psrc]!=p["ARP"].hwsrc:
                        countnum=countnum+1
        except:
            continue
    con, cur = dbcur()
    query = 'update attack_check set arp_spoofer_check= ' + str(countnum) + ' where id=0'
    cur.execute(query)
    con.commit()
    con.close()
def openssl():
    server=server_ssl()
    server.bulid_listen()

def main():
    p = multiprocessing.Process(target=capture_pcap)
    # p.daemon = True
    p.start()
    s = multiprocessing.Process(target=openssl)
    s.start()


con, cur = dbcur()
cur.execute('delete from pcap where 1=1')
cur.execute('update sqlite_sequence set seq=0 where name=\'pcap\'')
cur.execute('delete from attack where 1=1')
cur.execute('update sqlite_sequence set seq=0 where name=\'attack\'')
con.commit()
con.close()
PCAPNUMS = 0
main()