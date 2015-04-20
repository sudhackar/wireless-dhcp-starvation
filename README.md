# wireless-dhcp-starvation

This is an implementation of DHCP starvation attack on wireless network. This attack does not use the traditional random MAC vector.Instead it relies on sending a series of ACK-DECLINE.
arp.py is used when a Windows-PC connects to the network after the attacker.When the windows machine gets its lease, it ARPs the IP and asks for another IP if it gets the response.
dhcp.py simulates this process. It works even in the absence of other clients.

# screens attached
