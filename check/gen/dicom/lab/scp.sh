#!/bin/sh
ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1
tcpdump -i eth0 -s 0 -U -w /cap/$1.pcap 'tcp port 11112 or tcp port 11113' 2>/dev/null &
sleep 1
python3 /lab/scp.py > /cap/scp.log 2>&1
