import types
import requests
from socket import *
from bs4 import BeautifulSoup
import subfunc as sub
import urllib.request
import random

def webscan(urlname):
    r = requests.get(urlname)
    print("==============================")
    print("URL:", r.url)
    print("status_code:", r.status_code)
    print("headers:", r.headers)
    print("cookies:", r.cookies)
    print("==============================")

def portscan(urlname):
    print("==============================")
    s = socket(AF_INET, SOCK_DGRAM)
    urlname = sub.seperatehttp(urlname)
    s.connect((urlname, 80))
    port = [20, 21, 22, 23, 25, 40, 53, 70, 79, 80, 88, 110, 118, 123, 135, 137, 138, 139, 156, 161, 220, 443, 445, 514, 1433, 1521, 3306, 3389, 5357, 8080, 8090, 8443]
    host = urlname
    target_ip = gethostbyname(host)
    open_ports = []
    for p in port:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target_ip, p))
        if result == 0:
            open_ports.append(p)
    print("open_ports:", open_ports)
    print("==============================")

def dirscan(urlname):
    f = open("cheat_sheet/dir_scan_list.txt", "r")
    data = f.readline()
    while data != '':
        data = f.readline()
        r = requests.get(urlname+data)
        if r.status_code == 200:
            urlinfo = sub.deletesnl(r.url)
            print("You can connect at here!:", urlinfo)
            with open("connectdir/"+sub.seperatehttp(urlname)+".txt", "a+") as ss:
                ss.write(urlinfo+'\n')
    f.close()
    

def XSSscan(urlname):
    html = urllib.request.urlopen(urlname)
    soup = BeautifulSoup(html, "html.parser")
    for formtag in soup.findAll('form'):
        print('Using '+formtag.get('method')+' Method')
        if(formtag.get('method').upper() == 'GET'):
            print('GET Method Using... How about using POST?')
            with open('cheat_sheet/XSSpayload.txt', "r", errors="replace") as p:
                for i in p:
                    with open('connectdir/'+sub.seperatehttp(urlname)+".txt", "r", errors="replace") as d:
                        for j in d:
                            h = urllib.request.urlopen(j)
                            sp = BeautifulSoup(h, "html.parser")
                            for inputtag in sp.findAll('input'):
                                try:
                                    usrr = sub.get_user_agent()
                                    header = {"User-Agent": "{}".format(random.choice(usrr))}
                                    inputtagname = inputtag.get('name')
                                    attackurl = sub.deletesnl(urlname + "/" + formtag.get('action') + "?" + inputtagname + "=" + i)
                                    req = requests.get(attackurl, headers=header)
                                    
                                    if i in req.text:
                                        print("Parameter vulnerable\r\n")
                                        print("Vulneranle Payload Find\t: " + req.url)
                                        with open("vulnpayload/"+ 'GET-' +sub.seperatehttp(urlname)+".txt", "a+") as ss:
                                            ss.write(attackurl+"\n")
                                    else:
                                        print("TRYING\t:", req.url)
                                        
                                except:
                                    pass

        elif(formtag.get('method').upper() == 'POST'):
            print('POST Method Using... Make payload for it')
            with open('cheat_sheet/XSSpayload.txt', "r", errors="replace") as p:
                for i in p:
                    with open('connectdir/'+sub.seperatehttp(urlname)+".txt", "r", errors="replace") as d:
                        for j in d:
                            h = urllib.request.urlopen(j)
                            sp = BeautifulSoup(h, "html.parser")
                            for inputtag in sp.findAll('input'):
                                data = {}
                                inputtagname = inputtag.get('name')
                                if inputtagname is None:
                                    continue
                                data[inputtagname] = i
                                try:
                                    usrr = sub.get_user_agent()
                                    header = {"User-Agent": "{}".format(random.choice(usrr))}
                                    attackurl = sub.deletesnl(urlname + "/" + formtag.get('action'))
                                    req = requests.post(attackurl, headers=header, data=data)
                                    
                                    if i in req.text:
                                        print("Parameter vulnerable\r\n")
                                        print("Vulneranle Payload Find\t: " + req.url)
                                        with open("vulnpayload/"+ 'POST-' +sub.seperatehttp(urlname)+".txt", "a+") as ss:
                                            ss.write(attackurl + "\n" + inputtagname + ":" + i + "\n")
                                    else:
                                        print("TRYING\t:", req.url)
                                        
                                except:
                                    pass


def sqlscan(urlname):
    print("==============================")
    try:
        webpage = urllib.request.urlopen(urlname)
        urlsource = urlname.split('/')
        if(urlsource[-1] == 'admin'):
            print('admin label vuln')
        elif(urlsource[-1] == 'login'):
            print('login label vuln')
        else:
            soup = BeautifulSoup(webpage, "html.parser")
            for formtag in soup.findAll('form'):
                print('Using '+formtag.get('method')+' Method')
                if(formtag.get('method').upper() == 'GET'):
                    print('GET Method Using... How about using POST?')
                try:
                    response = requests.get(urlname+"'")
                    print('status_code:', response)
                    print('header:', response.headers)
                    statuscode = [404, 500, 408, 302]
                    if(response.status_code in statuscode):
                        print('There will be sql injection vuln...!')
                except:
                    print('There will be less probability')
    except:
        print('There is no ssl certificate...vuln!')
    print("==============================")


def crawling(urlname, tags):
    if len(tags) <= 0:
        print("There is no data in tags list")
        return
    html = requests.get(urlname)
    sp = BeautifulSoup(html.text, "html.parser")
    for tag in tags:
        for text in sp.select(tag):
            print("------------------------------")
            print(text)
            print("------------------------------")