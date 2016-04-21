import socket, ssl

bindsocket = socket.socket()
bindsocket.bind(('', 5555))
bindsocket.listen(5)

def RecvData():
    temp = connstream.read()
    #edit to handle "big" data
    return temp

while True:
    newsocket, fromaddr = bindsocket.accept()
    connstream = ssl.wrap_socket(newsocket,
                                 server_side=True,
                                 certfile="priv_dom.crt",
                                 keyfile="private_key.key")
    while True:
        inText = raw_input('[input] ')
        connstream.write(inText)
        outTT = RecvData()
        print '[outText] ' + outTT
        # make a function to handle exit
        #connstream.shutdown(socket.SHUT_RDWR)
        #connstream.close()
