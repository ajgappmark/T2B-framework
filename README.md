> Merge the power of Python with the anonymity of Tor.

##Status
[![Build Status](https://travis-ci.org/pielco11/T2B-framework.svg?branch=master)](https://travis-ci.org/pielco11/T2B-framework)

#TODO
- [ ] Correct compatibility with windows when executing commands
- [ ] Correct list files, change directory and reg key
- [-] Try/Except for importing libs (solved, using specific script)

#News
* 27/07/16:
   * Introcuted v2: many changes have come, added a lot of nice function (keylogging, extracting passwd from Firefox ...)
   * For a matter of compatibility I decided to write specific code for specific platforms (introducing Linux-Client, Windows-Client and Mac-Client)
* 21/07/16:
   * Corrected `HOOK`: now the script is handled with threads, no more external scripts or whatever. At the moment `HOOK` works only in Linux (that's why LinuxHOOKER), working on for windows.
   * Added `RunMe.sh`: automated tool to setup the HS, certificate and all the necessary
   * Added `VirusTotal check`: once the program is started, itself check is recognised as malware in the Database of [VirusTotal](https://www.virustotal.com/). Note that if the file was never scanned before, VT reports an "error". **You have to register on VT to get an api key**, [here](https://www.virustotal.com/en/documentation/public-api/) for more infos.
   * Added `HOOK` function: *still in dev*. Thanks to [JeffHoogland](https://github.com/JeffHoogland) for [pyxhook](https://github.com/JeffHoogland/pyxhook), at the time of writing you can check if hook is running or not, and if you want stop it.
   * Added `certificate auto extractor`: if the certificate.pem is not present in the directory, it'll extract form the code.
   * Fixed `s-wifi`: Thanks to [netifaces](https://pypi.python.org/pypi/netifaces) now you can check what netifaces are present and than choose the wifi card, no more if/ip-config.
* 14/07/16:
   * Added `LinuxAutoStart`: this will add a hidden .desktop in ~/.config/autostart/, and hidden in StarUp applications;
   * Added `WindowsAutoStart`: this will add a new reg key for the file, and set it hidden (_actually not tested at the time of writing_)
   * Added `FirefoxThief`: this will dump `key3.db`,`logins.json` and `cert8.db` from the specified directory. So then you can extract the passwd.
* 29/05/16:
   * Upgraded progress bar, thanks to [tqdm](https://github.com/tqdm/tqdm)
   * Added **HMAC** (coming for transfered files)
   * Added PBKDF to sign the hash of the files
* 24/05/16:
   * Added `protect` function, now you can encrypt & decrypt every file that you downloaded (in both directions) so you can keep safe your secrets (soon I'll add, obviously, **HMAC**)
* 05/05/16:
   * Added `s-wifi` that let you to scan the remote Wifi network;
   * Added `info` that let you retrieve some information about the target, like IP address and other OS information;
* 21/04/16:
Created v1 because reinvent the wheel is helpful but not useful.
So added **TLS**/**SSL** support to make a sense of real security. At the time of writing I'm using ssl std lib., but if there is a why that I shouldn't use it please tell me.

#Screen-shot
![Screenshot1](https://s32.postimg.org/cgvk00mo4/screen_mod.jpg)
![Screenshot2](https://s31.postimg.org/j7tnxj4xn/Schermata_da_2016_07_15_00_20_12.png)

#Description
This project aims to administrate a network of compromised hosts, keeping your identity private (thanks to Tor) and your connections secure (thanks to TLS/SSL). For many times botnets get stuck because the main servers became compromised, but this framework will let you keep yours C&C safe and alive (well, this will do its best).

Another _problem_ is that you let unauthorized users to reach your server, even without the cert or whatever. If I now your hostname/IP/whatever I can reach you. But **Tor** has the **solution** (that, as far as I know, clearnet hasn't). I'm referring to [HiddenServiceAuthorizeClient](https://www.torproject.org/docs/tor-manual.html.en#HiddenServiceAuthorizeClient) and [HidServAuth](https://www.torproject.org/docs/tor-manual.html.en#HidServAuth), if you set these properly, see [here](https://www.axs.org/tor/ssh_access_over_Tor.html),
your Master server will be more stealth than ever and it **won't** suffer ddos attack, or any other type of it. Because this is a feature of Tor, of the protocol and not of the software (T2B-framework).
So from now on, you'll setup a "_firewall_" between you (Master) and your bots. The new firewall will be just a node from you and your bots, that will filter "legit" client from attackers.
But for this we all will wait. News are coming, changes are coming.

#Motivation
Started looking for one... ended up writing one.

#Requirements
* Linux, Mac or Windows (not completely tested tested)
* Python 2.7
* [Tor](https://www.torproject.org/) and a HS.
* [Clint: Python Command-line Application Tools](https://github.com/kennethreitz/clint)
* [Colored](https://pypi.python.org/pypi/colored)
* [GeoIP](https://pypi.python.org/pypi/geoip2) and the [DB](https://dev.maxmind.com/geoip/geoip2/geolite2/)
* [Wifi, a Python interface](https://wifi.readthedocs.io/en/latest/)
* [OpenSSL](https://www.openssl.org/) to [generate Private Key and Cert](https://msol.io/blog/tech/create-a-self-signed-ssl-certificate-with-openssl/)
* [tqdm](https://github.com/tqdm/tqdm)
* getpass
* [simplejson](https://pypi.python.org/pypi/simplejson)
* [netifaces](https://pypi.python.org/pypi/netifaces) (for Linux and Mac wifi)
* [PyWiWi](https://github.com/6e726d/PyWiWi) (for Windows wifi)


#Installation
* Install Tor and initialize a HS
* Generate a S.S.C. (Self-Signed-Certificate) with Openssl (you can use the priv key of the HS)
* Modify the variables of the S.C. as you like (host, port, etc..)
* Install GEOIP2, and download the database
* run `pip install -r requirements`
* Install external (github) dependencies

#Contributors
I found a lot of code all over the web, so as soon as possible I'll add the reference to the main authors.
Last but not least, many people inspired me but citing everyone will crush the net.

#Known Bugs
- [ ] progress bar when uploading files, is not so progress

#Abuse
I'm **NOT** responsible for damages did by the abuse of this software.

#Contact me
You can find me on [Twitter](https://twitter.com/Pielco11) or you can add me on [Ricochet](https://ricochet.im/) `ricochet:cuu6hyttxg66ew6n`.
