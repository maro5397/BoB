import sys
import scanfunc as scan
import subfunc as sub
from time import sleep

class colors:
    r = '\033[31m'
    g = '\033[32m'
    y = '\033[33m'
    b = '\033[34m'
    m = '\033[35m'
    c = '\033[36m'
    w = '\033[37m'

def main():
    sub.entry()
    print(colors.m, end='')
    urlname = input("Give me your target url[ex) http://example.com]:")
    while True:
        sub.menu()
        id = input("Which one do you want to start?:")
        print(colors.w, end='')
        if id == "1":
            scan.webscan(urlname)
            sleep(1)
        elif id == "2":
            scan.portscan(urlname)
            sleep(1)
        elif id == "3":
            scan.dirscan(urlname)
            sleep(1)
        elif id == "4":
            tag = input("Which one do you want to find?:")
            scan.crawling(urlname, tag)
            sleep(1)
        elif id == "5":
            scan.sqlscan(urlname)
            sleep(1)
        elif id == "6":
            answer = input('Do you already make dirlist?(y/n):')
            if answer.upper() == 'Y' or answer.upper() == 'YES':
                scan.XSSscan(urlname)
            elif answer.upper() == 'N' or answer.upper() == 'NO':
                scan.dirscan(urlname)
                scan.XSSscan(urlname)
            sleep(1)
        elif id == "7":
            break
        else:
            print("Please select a valid option!")
    sys.exit()

if __name__ == '__main__':
    main()