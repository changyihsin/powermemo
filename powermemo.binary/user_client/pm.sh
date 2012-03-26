#network config
netcfg usb0 up
ifconfig usb0 $1

#adb connect
setprop service.adb.tcp.port 5555
stop adbd
start adbd

#powermemo.ko
./mknod /dev/powermemo c 249 0
insmod powermemo.ko
./mknod /dev/power c 200 0 
insmod power.ko
./poweragent $1 &



