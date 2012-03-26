#!/bin/sh
###export PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"
###export LD_LIBRARY_PATH="/lib:/usr/local/lib"
#ifconfig wlan0 down
#sleep 1
#ifconfig wlan0 up
#iwpriv wlan0 enc 1
#iwpriv wlan0 auth 1
#iwconfig wlan0 essid "dlink-BRASS"
#iwconfig wlan0 key s:54760
sleep 1
#udhcpc -i wlan0
#ifconfig wlan0 192.168.10.111
#route del default
#route add default gw 192.168.10.1 netmask 0.0.0.0 dev wlan0

#ping -c 2 140.113.1.1
ping -c 2 192.168.10.100


