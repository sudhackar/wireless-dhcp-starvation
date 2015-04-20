#!/bin/bash

while true; do
   #flush the previous IP address
   ifconfig wlan0 0.0.0.0

   # kill all running dhcp clients - just in case
   killall dhclient
   rm -f /var/run/dhclient.pid

   # bring down the interface
   ifconfig wlan0 down

   # change the MAC address of the interface and print the new MAC address
   macchanger -a wlan0 2>&1 | grep Faked

   # bring the interface up
   ifconfig wlan0 up

   #connect to the network
   iwconfig wlan0 essid "linksys"

   # make a new DHCP lease
   dhclient wlan0 2>&1 | grep DHCPACK

   #check IP address
   ifconfig wlan0 | grep "inet addr"
done