#!/bin/sh

kernel="./kernel_module"
user="./user_client"
for filename in `ls ${kernel}`
do
	echo installing $filename 
	adb push ${kernel}/${filename} /data/powermemo
done;

for filename in `ls ${user}`
do
	echo installing $filename 
	adb push ${user}/${filename} /data/powermemo
done;
    
