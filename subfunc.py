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