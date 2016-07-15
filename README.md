> Merge the power of Python with the anonymity of Tor.

##News
* 14/07/16:
   1. Added `LinuxAutoStart`: this will add a hidden .desktop in ~/.config/autostart/, and hidden in StarUp applications;
   2. Added `WindowsAutoStart`: this will add a new reg key for the file, and set it hidden (_actually not tested at the time of writing_)
   3. Added `FirefoxThief`: this will dump `key3.db`,`logins.json` and `cert8.db` from the specified directory. So then you can extract the passwd.
* 29/05/16:
   1. Upgraded progress bar, thanks to [tqdm](https://github.com/tqdm/tqdm)
   2. Added **HMAC** (coming for transfered files)
   3. Added PBKDF to sign the hash of the files
* 24/05/16:
   1. Added `protect` function, now you can encrypt & decrypt every file that you downloaded (in both directions) so you can keep safe your secrets (soon I'll add, obviously, **HMAC**)
* 05/05/16:
   1. Added `s-wifi` that let you to scan the remote Wifi network;
   2. Added `info` that let you retrieve some information about the target, like IP address and other OS information;
* 21/04/16:
Created v1 because reinvent the wheel is helpful but not useful.
So added **TLS**/**SSL** support to make a sense of real security. At the time of writing I'm using ssl std lib., but if there is a why that I shouldn't use it please tell me.

##Screen-shot
![Screenshot1](https://s32.postimg.org/cgvk00mo4/screen_mod.jpg)
![Screenshot2](https://s31.postimg.org/j7tnxj4xn/Schermata_da_2016_07_15_00_20_12.png)

##Description
This project aims to administrate a network of compromised hosts, keeping your identity private (thanks to Tor) and your connections secure (thanks to TLS/SSL). For many times botnets get stuck because the main servers became compromised, but this framework will let you keep yours C&C safe and alive (well, this will do its best).

Another _problem_ is that you let unauthorized users to reach your server, even without the cert or whatever. If I now your hostname/IP/whatever I can reach you. But **Tor** has the **solution** (that, as far as I know, clearnet hasn't). I'm referring to [HiddenServiceAuthorizeClient](https://www.torproject.org/docs/tor-manual.html.en#HiddenServiceAuthorizeClient) and [HidServAuth](https://www.torproject.org/docs/tor-manual.html.en#HidServAuth), if you set these properly, see [here](https://www.axs.org/tor/ssh_access_over_Tor.html),
your Master server will be more stealth than ever and it **won't** suffer ddos attack, or any other type of it. Because this is a feature of Tor, of the protocol and not of the software (T2B-framework).
So from now on, you'll setup a "_firewall_" between you (Master) and your bots. The new firewall will be just a node from you and your bots, that will filter "legit" client from attackers.
But for this we all will wait. News are coming, changes are coming.

##Motivation
Started looking for one... ended up writing one.

##Requirements
* Linux/OS X (Windows not tested)
* Python 2.7
* [Tor](https://www.torproject.org/) and a HS.
* [Clint: Python Command-line Application Tools](https://github.com/kennethreitz/clint)
* [Colored](https://pypi.python.org/pypi/colored)
* [GeoIP](https://pypi.python.org/pypi/geoip2) and the [DB](https://dev.maxmind.com/geoip/geoip2/geolite2/)
* [Wifi, a Python interface](https://wifi.readthedocs.io/en/latest/)
* [OpenSSL](https://www.openssl.org/) to [generate Private Key and Cert](https://msol.io/blog/tech/create-a-self-signed-ssl-certificate-with-openssl/)
* [tqdm](https://github.com/tqdm/tqdm)
* getpass

##Installation
* Install Tor and initialize a HS
* Generate a S.S.C. (Self-Signed-Certificate) with Openssl (you can use the priv key of the HS)
* Modify the variables of the S.C. as you like (host, port, etc..)
* Install GEOIP2, and download the database
* Install colored and clint
* Install wifi to scan the remote wifi area

##Contributors
I found a lot of code all over the web, so as soon as possible I'll add the reference to the main authors.
Last but not least, many people inspired me but citing everyone will crush the net.

##Known Bugs
* wifi card in s-scan (see code..)
* progress bar when uploading files, is not so progress 

##Abuse
I'm **NOT** responsible for damages did by the abuse of this software.

##Contact me
You can find me on Twitter or you can add me on [Ricochet](https://ricochet.im/) ricochet:cuu6hyttxg66ew6n.
