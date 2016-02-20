#!/usr/bin/env python
import socket, sys, os, time, socks, hmac, hashlib
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
		HM1 = hmac.new(key, info, hashlib.sha256)
		info1 = info + HM1.digest() + zero
		sock.sendall(info1)

def SendTextCipher(info2):
		HM2 = hmac.new(key, info2, hashlib.sha256)
		info1 = info2 + HM2.digest() + zero
		info = Encrypt(info1)
		sock.sendall(info)

def RecvTextCipher():
		l1 = sock.recv(size)
		l = Decrypt(l1)
		data = ""
		while(l):
			data += l
			if data.endswith(zero) == True :
				break
			else :
				l = sock.recv(size)
		endback = len(zero) + 32
		CheckString(data[:-len(zero)])
		return data[:-endback]

def RecvIV():
		l = sock.recv(size)
		data = ""
		while(l):
			data += l
			if data.endswith(zero) == True :
				break
			else :
				l = sock.recv(size)
		endback = len(zero) + 32
		CheckString(data[:-len(zero)])
		return data[:-endback]

def CheckString(check):
		gntkrjngrkt = hmac.new(key, check[:-32], hashlib.sha256)
		HM3 = hmac.new(key, check[:-32], hashlib.sha256)
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

zero = "zero"
key = ',U\x10\xab\xf6\xc6D\x08\xa7\xb7\xa36\xd6\t\x12\xaa'
name = 'client000-crypt' 
port = 5555
size = 4096
sock = socks.socksocket()
#if tor is not running, just comment out the next row
sock.setproxy(socks.PROXY_TYPE_SOCKS5,"127.0.0.1",9050)
#and change this next one
host = "3pnzz**********.onion" 
sock.connect((host,port))
iv = RecvIV()
cipher = AES.new(key, AES.MODE_CBC, iv)

while 1:
	data1 = raw_input("[client]: ")
	if data1 == "terminate":
		SendTextCipher(name + " :: " + data1)
		sock.close()
		sys.exit()
	else:
		SendTextCipher(name + " :: " + data1)
		data = RecvTextCipher()
		print "[recv]: " + data
s.close()
