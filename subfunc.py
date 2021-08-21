import sys
import re
from time import sleep

class colors:
    r = '\033[31m'
    g = '\033[32m'
    y = '\033[33m'
    b = '\033[34m'
    m = '\033[35m'
    c = '\033[36m'
    w = '\033[37m'

def seperatehttp(urlname):
    nonehttp = urlname.replace("https://", "")
    nonehttp = urlname.replace("http://", "")
    nonehttp = re.sub("\/.*", "", nonehttp)
    return nonehttp

def get_user_agent():
    try:
        lines = [line.rstrip("\n") for line in open("cheat_sheet/useragent.txt")]
    except IOError as e:
        print("User Agent error: %s" % e.strerror)
        sys.exit(1)
    return lines

def deletesnl(urlname):
    urlname = urlname.replace("#", "")
    urlname = urlname.replace("%0A", "")
    urlname = urlname.replace("\n", "")
    return urlname

def entry():
    banner = colors.g + """
           ╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱
           ╱╱┌━━━━━━━┳━━━━━━━┳━━━━━━━╮┌━━━╭━━╮╱╭━╮╱╭━━━━╮╱╱
           ╱╱┃  ╭━╮  ┃  ╭━╮  ┃  ╭━╮  ┃┃╭━╮┃  ┃╭╯ ╰╮┃ ╭╮ ┃╱╱
           ╱╱┃  ╰━╯ ╭┃  ┃╱┃  ┃  ╰━╯ ╭╯┃╰━━┫╭━╯┃ ┃ ┃┃ ┃┃ ┃╱╱
           ╱╱┃  ╭━╮ ╰┃  ┃╱┃  ┃  ╭━╮ ╰╮╰━━╮┃╰━╮╯╭━╮╰┫ ┃┃ ┃╱╱
           ╱╱┃  ╰━╯  ┃  ╰━╯  ┃  ╰━╯  ┃┃╰━╯┃  ┃ ┃╱┃ ┃ ┃┃ ┃╱╱
           ╱╱└━━━━━━━┻━━━━━━━┻━━━━━━━╯└━━━╰━━╯━╯╱╰━┻━╯╰━╯╱╱
           ╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱
\n"""
    for c in banner:
        print(c, end='')
        sys.stdout.flush()
        sleep(0.0001)
    
    print(colors.c, end='')

    l = "\t||||||||||||||||||||||||||||||||||||||||||||||||||||||\n"
    for c in l:
        print(c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    i = "\t||                   WEB-SCANNING                   ||\n"
    for c in i:
        print(c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    l = "\t||||||||||||||||||||||||||||||||||||||||||||||||||||||\n"
    for c in l:
        print(c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    i = "\t||               made by reindeer002!               ||\n"
    for c in i:
        print(c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    l = "\t||||||||||||||||||||||||||||||||||||||||||||||||||||||\n"
    for c in l:
        print(c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    i = "\t||               LET's SCANNING WEB!!               ||\n"
    for c in i:
        print(c, end='')
        sys.stdout.flush()
        sleep(0.0005)
    l = "\t||||||||||||||||||||||||||||||||||||||||||||||||||||||\n\n"
    for c in l:
        print(c, end='')
        sys.stdout.flush()
        sleep(0.0005)

def menu():
    print(colors.b, end='')
    print("-----------------------------------")
    print("|||            TOOLS            |||")
    print("-----------------------------------")
    menu = ("\n"
            "1)  WEBINFO\n"
            "2)  PORTSCAN\n"
            "3)  DIRSCAN\n"
            "4)  CRAWLING\n"
            "5)  SQLSCAN\n"
            "6)  XSS_SCAN\n"
            "7)  EXIT\n"
            "\n")
    for c in menu:
        print(colors.y + c, end='')
        sys.stdout.flush()
        sleep(0.0001)
    print(colors.r, end='')