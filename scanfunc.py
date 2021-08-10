import requests
from socket import *
from bs4 import BeautifulSoup
import subfunc as sub
from pprint import pprint
import urllib.request

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
    f = open("./dir_scan_list.txt", "r")
    data = f.readline()
    while data != '':
        data = f.readline()
        r = requests.get(urlname+data)
        if r.status_code == 200:
            print("You can connect at here!:", r.url)
    f.close()

def vulnerscan(urlname):
    html = urllib.request.urlopen(urlname)
    #need cheat sheet
    #using with urllib and show pprint

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