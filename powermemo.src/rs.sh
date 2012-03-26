#!bin/sh

sleep $2
echo "exec!"
$1 &
sleep $3
echo "kill!"
kill $!

