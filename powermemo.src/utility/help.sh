#!/bin/sh

for filename in ./*
do
	echo $filename 
	arm-eabi-objdump -d $filename > $filename.asm
	util_funandaddr -a $filename.asm > $filename.fun
done;
    
