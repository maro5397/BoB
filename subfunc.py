import sys
import re
import copy

def seperatehttp(urlname):
    nonehttp = urlname.replace("https://", "")
    nonehttp = urlname.replace("http://", "")
    nonehttp = re.sub("\/.*", "", nonehttp)
    return nonehttp

def maketaglist():
    taglist = copy.deepcopy(sys.argv)
    del taglist[0]
    del taglist[0]
    return taglist

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