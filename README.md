# wireless-dhcp-starvation

This is an implementation of DHCP starvation attack on wireless network. This attack does not use the traditional random MAC vector.Instead it relies on sending a series of ACK-DECLINE.
* arp.py is used when a Windows-PC connects to the network after the attacker.When the windows machine gets its lease, it ARPs the IP and asks for another IP if it gets the response.
* dhcp.py simulates this process. It works even in the absence of other clients.
* dhcp.sh and dhcp_wep.sh use traditional attack vector using random MAC. However the attacker loses network connectivity.


# screens attached
![screen-1](/screen-1.png?raw=true "Screenshot-1")
![screen-2](/screen-2.png?raw=true "Screenshot-2")