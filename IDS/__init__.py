from scapy.all import sniff,rdpcap,wrpcap
import os
from IDS.db import *
import multiprocessing
import time
from .views import analysis_http_attack,analysis,analysis_sql
import operator
def analysis_pcap(pcaps):
    PCAPNUMS = len(pcaps)
    con, cur = dbcur()
    query = 'update pcapsnum set num= ' + str(PCAPNUMS) + ' where id=0'
    # print(query)
    cur.execute(query)
    con.commit()
    con.close()
    analysis(pcaps)
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
    sorted= sorted(srclist.iteritems(), key=operator.itemgetter(1), reverse=True)
    count=0
    for key,value in sorted:
        if value > 500:
            con, cur = dbcur()
            query = '''insert into ipv6dos(src,num) values(key,value)'''
            cur.execute(query)
            con.commit()
            con.close()
        count=1
        if count==1:
            break
def flood_router6(pcaps):
    sumnum=len(pcaps)
    countnum=0
    for pcap in pcaps:
        if pcap.haslayer("IPv6"):
            try:
                if pcap.haslayer("ICMPv6ND_RA"):
                    if pcap["IPv6"].dst=="ff02::1" and pcap["ICMPv6ND_RA"].type==134:
                        countnum=countnum+1
            except:
                continue
    if countnum>((sumnum/3)*2):
        con, cur = dbcur()
        query = 'update ipv6_attack set floodrouter6_num= ' + str(countnum) + ' where id=0'
        cur.execute(query)
        con.commit()
        con.close()
def parasite6(pcaps):
    ndp_table=dict()
    ndpmac_table=dict()
    countnum=0
    for pcap in pcaps:
        try:
            if pcap.haslayer("IPv6"):
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
    query = 'update ipv6_attack set ndpspoofer_num= ' + str(countnum) + ' where id=0'
    cur.execute(query)
    con.commit()
    con.close()
def capture_pcap():

    while True:  # os模块的getpid()可以获得该进程的进程号,os.ppid()可以获得该进程的父进程的进程号
        # print("---in 子进程1 PID: %d 父进程PID：%d" % (os.getpid(), os.getppid()))
        # time.sleep(5)
        pcap = sniff(iface='eth0',timeout=1)
        # time.sleep(1)
        FILE = 'demo.pcap'
        # os.system('sudo tcpdump -i eth0 -G 6  -w /var/tmp/%Y_%m%d_%H%M_%S.pcap ')
        wrpcap(FILE,pcap)
        pcaps = rdpcap(FILE)
        q = multiprocessing.Process(target=analysis_pcap,args=(pcaps,))
        q.start()
        # analysis(pcaps)
        # pcaps = rdpcap(FILE)
        # analysis(pcaps)

def main():
    p = multiprocessing.Process(target=capture_pcap)
    p.start()
    # p2 = multiprocessing.Process(target=test2)
    # p2.start()

    # p.daemon = True


con, cur = dbcur()
cur.execute('delete from pcap')
cur.execute('update sqlite_sequence set seq=0 where name=\'pcap\'')
cur.execute('delete from attack')
cur.execute('update sqlite_sequence set seq=0 where name=\'attack\'')
con.commit()
con.close()
PCAPNUMS = 0
main()