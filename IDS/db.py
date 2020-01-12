# from __future__ import unicode_literals

from django.test import TestCase
import sqlite3
# Create your tests here.

def dbcur():
    # con = sqlite3.connect(os.path.join(os.getcwd(),'db.sqlite3'))
    con = sqlite3.connect('/root/mysite-master/db.sqlite3') #修改为自己的地址
    con.text_factory = bytes
    return con,con.cursor()

def initdb():
    con, cur = dbcur()
    # init_pcap = "CREATE TABLE pcap(id INTEGER primary key autoincrement not null ,time char(20),proto char(10),src char(20),dst char(20),sport char(10),dport char(10),raw char(500))"

    # init_TCP = "CREATE TABLE tcp(id INTEGER  primary key  autoincrement not null ,time char(20),src char(20),dst char(20),raw char(500))"

    init_attack = "CREATE TABLE attack(id INTEGER  primary key  autoincrement not null ,time char(20),src char(20),dst char(20),info text, type  char(30))"
    # cur.execute(init_pcap)
    cur.execute(init_attack)
    con.commit()
    con.close()

# initdb()
# print(os.path.join(os.getcwd(),'db.sqlite3'))