from django.shortcuts import render
from django.http import HttpResponse,HttpResponseRedirect
import random
from scapy.all import rdpcap
import time
import os
from django.template import loader
from .db import *
import re
import json

# Create your views here.
port_list = {22:'SSH',80:'HTTP',53:'DNS'}

def dbexe(cur,query):
    cur.execute(query)
    return cur.fetchall()

def get_attack_num(request):
    query1 = 'select count(1) from attack where type="sql-injection"'
    query2 = 'select count(1) from attack where type="XSS"'
    query3 = 'select ipv6_flood_num,ipv6_ndp_spoofer_check from attack_check where id=0'
    query4 = 'select ipv6_dos_src,ipv6_dos_check,tcp_syn_check from attack_check where id=0'


    con, cur = dbcur()
    sqli_injection = dbexe(cur, query1)
    sqli_injextion_nums = sqli_injection[0][0]

    xss_injection = dbexe(cur, query2)
    xss_injextion_nums = xss_injection[0][0]

    ipv6_attack = dbexe(cur,query3)
    check_flood_num = ipv6_attack[0][0]
    check_ndpspoofer = ipv6_attack[0][1]
    if(check_ndpspoofer!=0):
        check_ndpspoofer = 1
    if(check_flood_num!=0):
        check_flood_num =1

    ipv6_dos = dbexe(cur,query4)
    check_ipv6_dos = ipv6_dos[0][1]
    ipv6_dos_src = ipv6_dos[0][0].decode()
    tcp_syn_check = ipv6_dos[0][2]

    if(check_ipv6_dos!=0):
        check_ipv6_dos =1
    if(tcp_syn_check!=0):
        tcp_syn_check = 1

    print(check_ipv6_dos,ipv6_dos_src)



    con.commit()
    con.close()

    returndata = {
        'sqlinum':sqli_injextion_nums,
        'IPv6':random.randint(1,10),
        'xssnum':xss_injextion_nums,
        'codeinum':random.randint(1,10),
        'check_flood_router6': check_flood_router6,
        'check_ndpspoofer':check_ndpspoofer,
        'check_ipv6_dos':check_ipv6_dos,
        'ipv6_dos_src':ipv6_dos_src,
        'tcp_syn':tcp_syn_check,
    }
    # return HttpResponse(sqli_injextion_nums)
    return HttpResponse(json.dumps(returndata),content_type='application/json')



def index(request):
#show attack_res
    query = 'select id,time,src,dst,info,type from attack'
    query1 = 'select count(1) from attack where type="sql-injection"'
    query2 = 'select count(1) from attack where type="XSS"'
    query3 = 'select count(1) from attack where type="code-injection"'

    # query4 = 'select count(1) from attack where type="-injection"'
    con, cur = dbcur()
    # cur.execute(query)
    # attack_res = cur.fetchall()
    attack_res = dbexe(cur,query)

    attack_res = [list(x) for x in attack_res]

    sqli_injection = dbexe(cur,query1)
    sqli_injextion_nums = sqli_injection[0][0]

    xss_injection = dbexe(cur,query2)
    xss_injection_nums = xss_injection[0][0]

    code_injection = dbexe(cur,query3)
    code_injection_nums = code_injection[0][0]

    IPv6_attack_num = 0

    con.commit()
    con.close()
    for i in range(len(attack_res)):
        for j in range(1, len(attack_res[i])):
            try:
                attack_res[i][j] = attack_res[i][j].decode()
            except:
                attack_res[i][j] = attack_res[i][j]
        # res[i][-1].decode()

#show by charts
    returndata = {
        "TITLE": "SHOW",
        'title': 'Those are pcaps record',
        'attack_res': attack_res,
        'sqlinject_num':sqli_injextion_nums,
        'IPv6_DOS_num':IPv6_attack_num,
        'xss_num':xss_injection_nums,
        'codeinjection':code_injection_nums,
    }

    return render(request, 'IDS/index.html', returndata)

def add_recode(request):

    return 0


def mysniff(request):
    if request.POST:
        num = int(request.POST['number'])
        FILE = 'demo.pcap'
        pcaps = rdpcap(FILE)
        analysis(pcaps)

        return HttpResponseRedirect("/IDS/index/")
    else:
        return render(request, 'IDS/sniff.html')

def upload(request):
    if request.method == 'POST':
        file = request.FILES.get('file',None)
        if(file!=None):
            filepath = ""
            try:
                filename = 'pcaps.pacp'
                filepath = os.path.join('/root/PycharmProjects/mysite/',filename)
                f = open(filepath, 'wb')
                for i in file.chunks():
                    f.write(i)
                f.close()
            except:
                return HttpResponse('upload fail')
            try:
                anaylsis_from_file(filepath)

            except:
                return HttpResponse('filepath error')

            return HttpResponseRedirect("IDS/show/")
        else:
            return render(request, 'IDS/upload.html', {})
    else:
        return render(request, 'IDS/upload.html', {})

def anaylsis_from_file(file_path):
    pcaps = rdpcap(file_path)
    analysis(pcaps)
    return HttpResponseRedirect("/IDS/show/")


def show(request):
    # mktags()
    query = 'select id,time,proto,src,dst from pcap'
    con, cur = dbcur()
    cur.execute(query)
    res = cur.fetchall()
    res = [list(x) for x in res]
    con.commit()
    con.close()
    for i in range(len(res)):
        for j in range(1,len(res[i])):
            res[i][j] = res[i][j].decode()
        # res[i][-1].decode()
    return render(request, 'IDS/table.html', {"TITLE": "SHOW", 'title': 'Those are pcaps record', 'pcaps': res})


def show_attack(request):
    # mktags()
    query = 'select id,time,src,dst,info from attack'
    con, cur = dbcur()
    cur.execute(query)
    res = cur.fetchall()
    res = [list(x) for x in res]
    con.commit()
    con.close()
    for i in range(len(res)):
        for j in range(1,len(res[i])):
            res[i][j] = res[i][j].decode()
        # res[i][-1].decode()
    return render(request, 'IDS/index.html', {"TITLE": "SHOW", 'title': 'Those are pcaps record', 'pcaps': res})


def analysis(pcaps):

    protodic = {'1': 'ICMP', '6': 'TCP', '17': 'UDP'}
    con, cur = dbcur()

    sql_attack_num = 0
    xss_attack_num = 0
    IPv6_num = 0
    for pcap in pcaps:
        ptime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(pcap.time)))

        if pcap.haslayer('Raw'):
            info = pcap["Raw"].load
        else:
            info = "NULL"
        ptime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(pcap.time)))

        query = '''insert into pcap(time,proto,src,dst,sport,dport,raw) values(?,?,?,?,?,?,?)'''

        try:
            cur_proto = str(protodic.get(str(pcap.proto), "Other"))
        except:
            cur_proto = "TCP"
        # if(pcap.haslayer("IPv6")):
        #     IPv6_num
        try:
            if (b"GET " == info[:4] or b'POST' == info[:4] or b"HTTP" == info[:4]):
                cur_proto = "HTTP"
        except:
            cur_proto = "Other"
        try:
            cur_sp = str(pcap['IP'].sport)
        except:
            cur_sp = "NULL"
        try:
            cur_dp = str(pcap['IP'].dport)
        except:
            cur_dp = "NULL"
        try:
            srcip = str(pcap['IP'].src)
        except:
            srcip = "Unknow"
        try:
            dstip = str(pcap["IP"].dst)
        except:
            dstip = "Unknow"

        para = (ptime, cur_proto, srcip, dstip, cur_sp, cur_dp, info)
        cur.execute(query, para)


        results = analysis_http_attack(pcap)
        # print(results)
        if results!='safe' or results==None:
            if results[1]=='sql-injection':
                sql_attack_num+=1
            elif results[1]=='XSS':
                xss_attack_num+=1
            print('not safe')
            print(results)
            try:
                info,type = results[0],results[1]
                query1 = '''insert into attack(time,src,dst,info,type) values(?,?,?,?,?)'''
                para1 = (ptime, srcip, dstip, info, type)
                cur.execute(query1, para1)
            except:
                pass
    cur.execute('update attack_check set sql_attack_num= ' + str(sql_attack_num) + ' where id=0')
    cur.execute('update attack_check set xss_attack_num= ' + str(xss_attack_num) + ' where id=0')
    con.commit()
    con.close()



def analysis1(request):

    return render(request,'IDS/chart.html',{})

def attacklogs(request):
    query = 'select * from attack'
    con, cur = dbcur()
    cur.execute(query)
    result = cur.fetchall()

    template = loader.get_template('IDS/attacklog.html')

    return HttpResponse(template.render({'pcaps':result}),request)

#------------------------detect-sqlinjection----------------------------#
sql_attack_regx = r'if|is|not|union|like|having|sleep|regexp|ascii|left|select|right|strcmp|substr|limit|instr|benchmark|oct|format|lpad|rpad|\|\||mod|insert|lower|bin|mid|hex|substring|ord|and|field|file|char|in|or|exists|xor|table_schema|where|table_name|column_name|--|`|<|>|<>|\|/|&|{|}|\(|\)|~|sel<>ect|seleselectct|sEleCt|%09|%0a|%0b|%0c|%0d|%20|%a0|information_schema|join'
xss_attack_regx = r'?|>|<|alert|applet|body|embed|frame|script|frameset|html|iframe|img|style|layer|link|ilayer|meta|object|alertonresize|ondragenter|onreadystatechange|ondrop|onmouseout|onseeked|onseeking|onpageshow|onFocus|oninput|onstorage|onwaiting|onforminput|onpropertychange|onplay|onbeforeunload|ontextmenu|onMouseOver|onpaonpageonpagonpageonpageshowshoweshowshowgeshow|onResize|onblur|ondurationchange|onReadyStateChange|onerror|onratechange|onstart|onqt_error|onselect|onMouseMove|onplaying|onstalled|onmessage|onEnd|onfocus|onPageShow|onload|onloadstart|onBlur|onended|onbeforeload|oncut|onPageHide|onMouseUp|onbegin|onsearch|onUnload|onPopState|ont|onMouseLeave|onsuspend|ondragleave|onchrome|onchange|onwheel|ondragover|onpopstate|onMouseDown|onmousemove|onPropertyChange|onprogress|one|onmouseup|onscroll|ontenteditable|onMouseEnter|oncanplay|ondragend|oncuechange|onclick|ontimeupdate|onfilterchange|onpause|onreset|onBeforeUnload|onloadeddata|onScroll|onshow|oninvalid|onpaste|ononline|onmouseover|ondragstart|onvolumechange|onpagehide|oncopy|onsubmit|onemptied|onoffline|onMouseWheel|onLoad|onhashchange|onunload|ontent|onafterprint|onfinish|onMouseOut|ondrag|onmousedown|onError|onkeydown|ont-size|oncanplaythrough|onStart|onkeyup|oncontextmenu|onmousewheel|ondblclick|onkeypress|onloadedmetadata|onbeforeprint|ontoggle|onabort|'

# def test_sql_attact(request):




def analysis_sql_xss(uri,content):
    print(1)

    try:
        reqs = uri.split('?',1)[1]
    except:
        reqs = uri
    try:
        reqs = reqs.split('&')
        reqs = reqs
        try:
            for req in reqs:
                req = req.split('=',1)[1]

                result = re.search(sql_attack_regx, req, re.IGNORECASE)
                if (result!=None):
                    info =  req
                    return info,"sql-injection"
                else:
                    result = re.search(xss_attack_regx,req,re.IGNORECASE)
                    if(result!=None):
                        info = req
                        return info,"XSS"
                    else:
                        return 'safe'
        except:
            # try:
            #     reqs = content.split('&')
            #     for req in reqs:
            #         req = req.split('=', 1)[1]
            #         result = re.search(sql_attack_regx, req, re.IGNORECASE)
            #         if (result != None):
            #             info =  req
            #             return info
            #     return 'safe'
            # except:
            #     return 'safe'
            return 'safe'
    except:
        return 'safe'



def analysis_http_attack(i):
    if i.haslayer('TCP'):
        try:
            source=i['IP'].src
            destination = i['IP'].dst
            seq = i['TCP'].seq
            ack = i['TCP'].ack
            window = i['TCP'].window
        except:
            source = i['IPv6'].src
            destination = i['IPv6'].dst

        sport=i['TCP'].sport
        dport=i['TCP'].dport

        try:
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

                    type='http'
                    headers=other_info_dict
                    print(uri)
                    content=content

                    # print(http_req)
                    print("analysis sql")
                    results = analysis_sql_xss(uri=uri,content=content)
                    print(results)
                    xss = 0
                    if results!='safe':
                        print(results)
                        return results
                    return 'safe'
                else:
                    return 'safe'
            else:
                return 'safe'
        except:
            return 'safe'
    else:
        return 'safe'
#------------------------detect-sqlinjection----------------------------#


def getpcap_num(request):
    con, cur = dbcur()
    query = 'select num from pcapsnum where id=0'
    query2 = 'select num from pcapsnum where id=1'

    cur.execute(query)
    tcp_num = cur.fetchall()[0][0]
    cur.execute(query2)
    ipv6_num = cur.fetchall()[0][0]

    if(tcp_num>=1000):
        query1 = 'update attack_check set tcp_syn_check=1 where id=0'
        cur.execute(query1)

    PCAPNUM = {
        'tcp_num':tcp_num,
        'ipv6_num':random.randint(0,tcp_num)
    }
    con.commit()
    con.close()

    return HttpResponse(json.dumps(PCAPNUM),content_type='application/json')
