# scapyarpspoof
Simple effective ARP spoofer with scapy

I don't know if this will work on any other system. It works well on my Kali linux but code is hackish so just fix it if you have a problem.
Shows ARP spoofing in scapy nicely.

Simple use such as:  

  ./arpspoof.py -t 5
  
This will arpspoof x.x.x.5 on your network sending requests to the target and replies to the router. Classic MiTM using ARP packets.
