import socket, ssl, pprint, socks

host = '3pnzzdpq7aj6s6b6.onion'

def RecvData():
    temp = ssl_sock.read()
    # edit to handle "big" data 
    return temp

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
    print '[inText] ' + inText
    ssl_sock.write(inText)
    # def handle function to exit
#    ssl_sock.close()
