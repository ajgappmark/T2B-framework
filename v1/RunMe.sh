#!/bin/bash
echo "#######################"
echo "Updating & Upgrading..."
#apt-get update 2>&1 >/dev/null && apt-get upgrade -y 2>&1 >/dev/null
#apt-get dist-upgrade -y 2>&1 >/dev/null
echo "Installing pip..."
apt-get install python-pip -y 2>&1 >/dev/null
echo "#######################"
echo "[I]nstall OpenSSL from repository or [D]ownload the source? [i/d]"
read choose
if [ "$choose" == "i" ]; then
	apt-get install openssl -y
elif [ "$choose" == "d" -a "$choose" != "i" ]; then
	wget https://www.openssl.org/source/openssl-1.0.2h.tar.gz
	wget https://www.openssl.org/source/openssl-1.0.2h.tar.gz.sha256
	sha256sum openssl-1.0.2h.tar.gz && cat openssl-1.0.2h.tar.gz.sha256
	echo "Continue? [y/n]" && read varC
	if [ "$varC" == "y" ]; then
		tar –xvzf openssl-1.0.2h.tar.gz
		cd openssl-1.0.2h
		./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl
		make install
	else
		exit 1
	fi
else
	echo "Error input"
fi
echo "#######################"
echo "Setting up Tor HiddenService"
echo "Detectable, Hidden (basic) or Hidden (stealth)?  [d/b/s]"
read typeOfService
echo "Type the full directory of the HS: "
read directoryHS
echo "Type the real port of the HS: "
read RportHS
echo "Type the virtual port of the HS: "
read VportHS
if [ "$typeOfService" == "d" ]; then
	echo "HiddenServiceDir " + $directoryHS >> /etc/tor/torrc
	echo "HiddenServicePort " + RportHS + " 127.0.0.1 " + VportHS
	echo "Now run tor!"
	echo "Finished... closing"
	exit 0
elif [ "$typeOfService" == "b" ]; then
	echo "Type an username: "
	read username
	echo "HiddenServiceDir " + $directoryHS >> /etc/tor/torrc
        echo "HiddenServicePort " + RportHS + " 127.0.0.1 " + VportHS
	echo "HiddenServiceAuthorizeClient basic " + $username
	echo "Generated authorization data can be found in the hostname file."
 	echo "Clients need to put this authorization data in their configuration file using HidServAuth. "
        echo "Now run tor!"
        echo "Finished... closing"
        exit 0
else
	echo "Type an username: "
        read username
        echo "HiddenServiceDir " + $directoryHS >> /etc/tor/torrc
        echo "HiddenServicePort " + RportHS + " 127.0.0.1 " + VportHS
        echo "HiddenServiceAuthorizeClient stealth " + $username
        echo "Generated authorization data can be found in the hostname file. Clients need to put this authorization data in their configuration file using$
        echo "Now run tor!"
        echo "Finished... closing"
        exit 0
fi
echo "#######################"
echo "Setting up Certificate..."
$privKeyLoc = $directoryHS + private_key
openssl req -new -sha256 -key $privKeyLoc -out csr.csr
$csrLoc = $directoryHS + "csr.csr"
openssl req -x509 -sha256 -days 365 -key $privKeyLoc -in $csrLoc -out certificate.pem
echo "Move certificate.pem to the HS directory"
echo "Finished... closing"
exit 0
