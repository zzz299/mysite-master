import os
from .db import *
import re
import time





sql_attack_regx = r'if|is|not|union|like|having|sleep|regexp|ascii|left|select|right|strcmp|substr|limit|instr|benchmark|oct|format|lpad|rpad|mod|insert|lower|bin|mid|hex|substring|ord|and|field|file|char|in|or|exists|xor|table_schema|where|table_name|column_name|--|`|<|>|<>|\||\|/|&|{|}|\(|\)|~|sel<>ect|seleselectct|sEleCt|%09|%0a|%0b|%0c|%0d|%20|%a0|information_schema|join'

def analysis_sql(uri,content):
    try:
        reqs = uri.split('?',1)[1]
    except:
        reqs = uri
    try:
        reqs = reqs.split('&')
    except:
        reqs = reqs

    for req in reqs:
        req = req.split('=',1)[1]
        result = re.search(sql_attack_regx, req, re.IGNORECASE).groups()
        if (result!=None):
            info =  result
            return info

    # reqs = content.split('&')
    # for req in reqs:
    #     req = req.split('=', 1)[1]
    #     result = re.search(sql_attack_regx, req, re.IGNORECASE)
    #     if (result != None):
    #         info =  req
    #         return info
    return 'safe'

def analysis_http_attack(i):
    ptime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(i.time)))
    query = '''insert into pcap(time,src,dst,info,type) values(?,?,?,?,?)'''

    if i.haslayer('TCP'):
        source=i['IP'].src,
        destination=i['IP'].dst,
        sport=i['TCP'].sport,
        dport=i['TCP'].dport,
        seq=i['TCP'].seq,
        ack=i['TCP'].ack,
        window=i['TCP'].window


        if(i.haslayer('Raw')):
            type='GET'
            raw = i['Raw'].load
            if (b"GET " == i['Raw'].load[:4] or b'POST' == i['Raw'].load[:4]):
                # if b"GET " == raw[:4] or b'POST' == raw[:4]:
                if b'POST' == i['Raw'].load[:4]:
                    type='POST'

                info = str(raw).split("\r\n")
                uri = info[0].split(" ")[1]
                content = info[-1]
                other_info_dict = dict((x.split(":")[0], x.split(":")[1]) for x in info[1:] if ":" in x)
                host = ""
                if "Host" in other_info_dict:
                    host = other_info_dict["Host"]

                source=i['IP'].src,
                type='http',
                destination=i['IP'].dst,
                sport=i['TCP'].sport,
                dport=i['TCP'].dport,
                headers=other_info_dict,
                uri=uri,
                content=content,

                # print(http_req)
                result = analysis_sql(uri=uri,content=content)
                if result!='safe':
                    sql_result = result
                    type = 'SQL-injection'
                    para = (ptime, source, destination, sql_result,type)
                    cur.execute(query, para)


if '__name__' == '__main__':

    con, cur = dbcur()
    cur.execute('delete from attack')
    cur.execute('update sqlite_sequence set seq=0 where name=\'attack\'')

    con.commit()
    con.close()


