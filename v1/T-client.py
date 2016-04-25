import socket, ssl, pprint, socks

host = '3pnzzdpq7aj6s6b6.onion'

def RecvData():
    temp = ssl_sock.read()
    # edit to handle "big" data 
    return temp

def SendData(inText):
    ssl_sock.write(inText)

def UploadFILE(fileName):
    fileUP = open(fileName, 'rb')
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
    SendData("CDF") #Client Download Finished

sock = socks.socksocket()
sock.setproxy(socks.PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
sock.connect((host,5555))

# Require a certificate from the server. We used a self-signed certificate so here ca_certs must be the server certificate itself.
ssl_sock = ssl.wrap_socket(sock,
                           ca_certs="priv_dom.crt",
                           cert_reqs=ssl.CERT_REQUIRED)

print repr(ssl_sock.getpeername())
print ssl_sock.cipher()
print pprint.pformat(ssl_sock.getpeercert())

while 1:
	#ssl_sock.write("boo!")
    inText = RecvData()
    if inText.startswith("download"):
        UploadFILE(inText.split(" ")[1])
        chunk = RecvData()
    elif inText.startswith("upload"):
        DownloadFILE(inText.split(" ")[1])
    elif inText == "terminate":
        ssl_sock.close()
        sys.exit(0)
    else:
        print '[inText] ' + inText
        SendData(inText)
    # def handle function to exit
#    ssl_sock.close()
