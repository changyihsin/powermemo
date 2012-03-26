#!/bin/sh

echo "killing previous ntpclient and pmemo_client..."
#pkill ntpclient
pkill pmemo_client

#ilter here: Sync the OS clock and adjust the hw clock frequency                
#echo "running ntpclient for the first time..."
#/bin/ntpclient -s -h 192.168.0.10 -t                                            
#echo "sleeping for 5 sec..."      
#sleep 5                                                             
#echo "running ntpclient for the second time,now with -f..."
#/bin/ntpclient -f -3830019 -s -h 192.168.0.10 -t                                
#echo "putting ntpclient to background,it will sync every 30sec"                  
#/bin/ntpclient -f -3830019 -i 30 -h 192.168.0.10 -t > /dev/null &

#echo "mounting SD card partitions..."
#mount -t vfat /dev/sda1 /mnt/sda1
#mount -t vfat /dev/sdb1 /mnt/sdb1

echo "setting up wireless connection..."
#udevd &
#modprobe rt73usb
sh dlink.wlan0.sh

echo "inserting powermemo kernel module..."
insmod /mnt/sda1/powermemo.ko
cd /mnt/sda1/
echo "running powermemo user-daemon..."
./pmemo_client 192.168.0.10 8001 /dev/ttyS0 200 &
ps
echo "User-daemon pmemo_client should be running in the background now..."








