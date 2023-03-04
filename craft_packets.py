import socket
import struct
import array
import random
import subprocess
import datetime
import time



# CREDITS: https://github.com/bestbugwriter/python/blob/master/tcp.py and https://www.binarytides.com/python-syn-flood-program-raw-sockets-linux/
# FORMAT OF struct.pack(): https://docs.python.org/3/library/struct.html
# USEFUL DEBUGGING TOOL: https://hpd.gasmi.net/
# DEBUGGING EXAMPLE:
### CAPTURE SYN 		  -> tcpdump -n -c 1 -s 0 dst host 127.0.0.1 and port 4444 -w syn.pcap -i lo
### READ PACKET 		  -> tcpdump -r syn.pcap -X
### EDIT PACKET DST PORT  -> tcprewrite --infile=syn.pcap --outfile=syn2.pcap --portmap=4444:4445 --fixcsum
### SEE CHANGES 		  -> tcpdump -r syn2.pcap -X
### SEND CHANGED PACKET   -> tcpreplay --intf1=lo syn2.pcap
class TCP_SYN_PACK_SEND():

	# credits: https://github.com/secdev/scapy/blob/master/scapy/utils.py
	def _checksum(self, pkt):
		if len(pkt) % 2 == 1:
			pkt += b"\0"
		s = sum(array.array("H", pkt))
		s = (s >> 16) + (s & 0xffff)
		s += s >> 16
		s = ~s
		if struct.pack("H", 1) == b"\x00\x01":  # big endian
			checksum_endian_transform = lambda chk: chk  # type: Callable[[int], int]
		else:
			checksum_endian_transform = lambda chk: ((chk >> 8) & 0xff) | chk << 8
		return checksum_endian_transform(s) & 0xffff

	def __init__(self, dst_ipaddr, dst_port, payload=""):
		ip_route = subprocess.check_output(f'ip route get {dst_ipaddr}', shell=True).decode().split(' ')
		self.iface = ip_route[ip_route.index('dev') + 1]
		self.src_ipaddr = subprocess.check_output(f'ip -4 addr show {self.iface} | grep -oP "(?<=inet ).*(?=/)"', shell=True).decode().strip()
		self.src_port = random.randrange(30000,65536)
		self.dst_ipaddr = dst_ipaddr
		self.dst_port = dst_port
		self.payload = bytes(payload, 'utf-8')
		
		# IP HEADER (PRE CHECKSUM)
		id = random.randrange(0,65536)
		ip_header = struct.pack(
			'!BBHHHBBH4s4s', 						# the ! in the pack format string means network order
			0x45,									# Version 4	+ Internet Header Length    								(1 byte (B) = 8 bit)
			0x0,									# TOS: Type Of Service													(1 byte (B) = 8 bit)
			0x003c,									# Total length (Header IP + Header TCP + Data = 20 + 40 + 0)			(2 bytes (H) = 16 bit)
			id,										# Id of this packet														(2 bytes (H) = 16 bit)
			0x00,									# Flags OFF     														(2 bytes (H) = 16 bit)
			0x40,									# Time To Live counter = 64												(1 byte (B) = 8 bit)
			0x06,									# Protocol of the upper level, TCP=6									(1 byte (B) = 8 bit)
			0x00,									# Checksum (initial value)												(2 bytes (H) = 16 bit)
    		socket.inet_aton(self.src_ipaddr),      # Source Address														(4 bytes (4*s) = 32 bit)
    		socket.inet_aton(self.dst_ipaddr)       # Destination Address													(4 bytes (4*s) = 32 bit)
		)

		ip_checksum = self._checksum(ip_header)
		
		# IP HEADER (POST CHECKSUM)
		ip_header = struct.pack(
			'!BBHHHBBH4s4s', 						# the ! in the pack format string means network order
			0x45,									# Version 4	+ Internet Header Length    								(1 byte (B) = 8 bit)
			0x0,									# TOS: Type Of Service													(1 byte (B) = 8 bit)
			0x003c,									# Total length (Header IP + Header TCP + Data = 20 + 40 + 0)			(2 bytes (H) = 16 bit)
			id,										# Id of this packet														(2 bytes (H) = 16 bit)
			0x00,									# Flags OFF																(2 bytes (H) = 16 bit)
			0x40,									# Time To Live counter = 64												(1 byte (B) = 8 bit)
			0x06,									# Protocol of the upper level, TCP=6									(1 byte (B) = 8 bit)
			ip_checksum,							# Checksum (final value)												(2 bytes (H) = 16 bit)
    		socket.inet_aton(self.src_ipaddr),      # Source Address														(4 bytes (4*s) = 32 bit)
    		socket.inet_aton(self.dst_ipaddr)       # Destination Address													(4 bytes (4*s) = 32 bit)
		)
		
		# INITIAL TCP HEADER (PRE CHECKSUM)
		reserved1, reserved2, reserved3, nonce, cwr, ecn_echo, urg, ack, psh, rst, syn, fin = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0 #tcp flags
		tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5) + (ecn_echo << 6) + (cwr << 7) + (nonce << 8) + (reserved1 << 9) + (reserved2 << 10) + (reserved3 << 11)
		seqn = random.randrange(1000000,999999999)
		timestamp = int(time.mktime(datetime.datetime.now().timetuple()))
		tcp_header = struct.pack(
			'!HHLLBBHHHBBHBBBBLLBBBB',                       # the ! in the pack format string means network order
			self.src_port,                                   # Source Port 					(2 bytes (H) = 16 bit)
			self.dst_port,       							 # Destination Port 			(2 bytes (H) = 16 bit)
			seqn,								             # Sequence Number 				(4 bytes (L) = 32 bit)
			0x0000,                                          # Acknoledgement Number 		(4 bytes (L) = 32 bit)
			0xa0,		                                     # Doff 5x4x2 = 40 bytes        (1 byte (B) = 8 bit)
			tcp_flags,										 # TCP flags					(1 byte (B) = 8 bit)
			0xffd7,								 			 # Window size = 65495		    (2 bytes (H) = 16 bit)
			0x00,                                            # Checksum (initial value)		(2 bytes (H) = 16 bit)
			0x00,                                            # Urgent pointer				(2 bytes (H) = 16 bit)
			0x2,											 # MSS: kind=2					(1 byte (B) = 8 bit)
			0x4,											 # MSS: length=4				(1 byte (B) = 8 bit)
			0xffd7,											 # MSS: 65495					(2 bytes (H) = 16 bit)
			0x4,											 # SACK permitted: kind=4		(1 byte (B) = 8 bit)
			0x2,											 # SACK permitted: length=2		(1 byte (B) = 8 bit)
			0x8,											 # Timestamps: kind=8			(1 byte (B) = 8 bit)
			0xa,											 # Timestamps: length=10    	(1 byte (B) = 8 bit)
			timestamp,										 # Timestamps:              	(4 bytes (L) = 32 bit)
			0x0,     										 # Timestamps: echo_reply=0		(4 bytes (L) = 32 bit)
			0x1,											 # NOP							(1 byte (B) = 8 bit)
			0x3,											 # Window scale: kind=3			(1 byte (B) = 8 bit)
			0x3,											 # Window scale: lemgth=3		(1 byte (B) = 8 bit)
			0x7,											 # Window scale: shiftc=7		(1 byte (B) = 8 bit)
		)
		
		# TCP PSEUDO HEADER
		pseudo_hdr = struct.pack(
    		'!4s4sBBH',								         # the ! in the pack format string means network order
    		socket.inet_aton(self.src_ipaddr),               # Source Address				 (4 bytes (4*s) = 32 bit)
    		socket.inet_aton(self.dst_ipaddr),               # Destination Address		     (4 bytes (4*s) = 32 bit)
    		0x0,                                             # Reserved					     (1 byte (B) = 8 bit)
    		0x06,                        			         # Protocol ID, TCP=6	    	 (1 byte (B) = 8 bit)
    		len(tcp_header) + len(self.payload)              # TCP Length				     (2 bytes (H) = 16 bit)
		)

		pseudo_hdr = pseudo_hdr + tcp_header + self.payload
		tcp_checksum = self._checksum(pseudo_hdr)
		
		# FINAL TCP HEADER (POST CHECKSUM)
		tcp_header = struct.pack(
			'!HHLLBBHHHBBHBBBBLLBBBB',          			 # the ! in the pack format string means network order
			self.src_port,                                   # Source Port 					(2 bytes (H) = 16 bit)
			self.dst_port,       							 # Destination Port 			(2 bytes (H) = 16 bit)
			seqn,								             # Sequence Number 				(4 bytes (L) = 32 bit)
			0x0000,                                          # Acknoledgement Number 		(4 bytes (L) = 32 bit)
			0xa0,		                                     # Doff 5x4x2 = 40 bytes        (1 byte (B) = 8 bit)
			tcp_flags,										 # TCP flags					(1 byte (B) = 8 bit)
			0xffd7,								 			 # Window size = 65495		    (2 bytes (H) = 16 bit)
			tcp_checksum, 									 # Checksum (final value)		(2 bytes (H) = 16 bit)
			0x00,                                            # Urgent pointer				(2 bytes (H) = 16 bit)
			0x2,											 # MSS: kind=2					(1 byte (B) = 8 bit)
			0x4,											 # MSS: length=4				(1 byte (B) = 8 bit)
			0xffd7,											 # MSS: 65495					(2 bytes (H) = 16 bit)
			0x4,											 # SACK permitted: kind=4		(1 byte (B) = 8 bit)
			0x2,											 # SACK permitted: length=2		(1 byte (B) = 8 bit)
			0x8,											 # Timestamps: kind=8			(1 byte (B) = 8 bit)
			0xa,											 # Timestamps: length=10    	(1 byte (B) = 8 bit)
			timestamp,										 # Timestamps:              	(4 bytes (L) = 32 bit)
			0x0,     										 # Timestamps: echo_reply=0		(4 bytes (L) = 32 bit)
			0x1,											 # NOP							(1 byte (B) = 8 bit)
			0x3,											 # Window scale: kind=3			(1 byte (B) = 8 bit)
			0x3,											 # Window scale: lemgth=3		(1 byte (B) = 8 bit)
			0x7,											 # Window scale: shiftc=7		(1 byte (B) = 8 bit)
		)

		# SEND PACKET
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		try:
			s.sendto(ip_header+tcp_header, (self.dst_ipaddr, 0))
		except socket.timeout:
			self.status = 'filtered'
		else:
			received_bytes = s.recv(1024)
			s.close()
			print(f'SENDED: {" ".join([str(hex(x)).replace("0x", "").upper().rjust(2, "0") for x in ip_header+tcp_header])}')
			print(f'RECVED: {" ".join([str(hex(x)).replace("0x", "").upper().rjust(2, "0") for x in received_bytes])}')

		# DECODE RECEIVED BYTES
		response_upper_protocol = struct.unpack('!BBHHHBBH4s4s', received_bytes[0:20])[6]
		if response_upper_protocol == 1: #ICMP
			received_icmp_header = struct.unpack('!BB', received_bytes[20:22]) # need only type and code
			if received_icmp_header[0] == 3 and received_icmp_header[1] in [0, 1, 2, 3, 9, 10, 13]:
				self.status = 'filtered'
		elif response_upper_protocol == 6: #TCP
			received_tcp_header = struct.unpack('!HHLLBBHHH', received_bytes[20:40]) # don't care about options
			control_flags = { 32:"U", 16:"A", 8:"P", 4:"R", 2:"S", 1:"F" }
			flags = list()
			for f in control_flags:
				if received_tcp_header[5] & f: # check if bit is 1
					flags += control_flags[f]
			print(flags)
			if 'S' in flags and 'A' in flags:
				self.status = 'open'
			if 'R' in flags and 'A' in flags:
				self.status = 'closed'
			if not hasattr(self, 'status'):
				self.status = 'different response'
		else:
			self.status = 'different response'


# TODO: still debugging because linux localhost doesn't reply to the TCP-SYN
print(TCP_SYN_PACK_SEND('127.0.0.1', 4444).status)