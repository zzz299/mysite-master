from scapy.all import sniff,rdpcap,wrpcap
import os
from IDS.db import *
import multiprocessing
import time




if __name__ == "__main__":
    pwd = os.getcwd()+'/pcapdir/'
    print(pwd)
    dir = 'sudo tcpdump -i eth0 -G 6  -w '+ pwd +'demo.pcap'
    print(dir)
