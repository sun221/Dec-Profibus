import getopt
import sys , os
import getopt
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
from layers.UseSerial import *


devp=None

def vlenq2str(l):
    s = []
    s.append( hex(l & 0x7F) )
    l = l >> 7
    while l>0:
        s.append( hex(0x80 | (l & 0x7F) ) )
        l = l >> 7
    s.reverse()
    return "".join(chr(int(x, 16)) for x in s)
    
def str2vlenq(s=""):
    i = l = 0
    while i<len(s) and ord(s[i]) & 0x80:
        l = l << 7
        l = l + (ord(s[i]) & 0x7F)
        i = i + 1
    if i == len(s):
        warning("Broken vlenq: no ending byte")
    l = l << 7
    l = l + (ord(s[i]) & 0x7F)
    return s[i+1:], l 


def bytes_to_int(bytes):	
	"""Byte format to int"""
	result = 0
	for b in bytes:
		result = result * 256 + int(b)
	return result

def int_to_bytes(value, length):
	"""Int format to Byte"""
	result = []

	for i in range(0, length):
		result.append(value >> (i * 8) & 0xff)

	result.reverse()

	return result

def packet_to_dict(packet):  #{"SD":"SD2","LE":0,"DA":0,"SA":0,"FC":0x49,"DSAP":0,"SSAP":0,"DU":0,"Valid":"","Error":""}
	"""Convert from Scapy format to dictionary format"""
	packet=FdlSd1(raw(packet))
	sd = packet.SD
	
	dictFormat = {}
	if sd == FdlSd1.SD1:
		dictFormat['SD'] =FdlSd1.SD1
		dictFormat['DA'] = packet.DA
		dictFormat['SA'] = packet.SA
		dictFormat['FC']= packet.FC
		dictFormat['Valid'] = True
		dictFormat['error'] = ""
		# No DU
		if len(packet) != 6:
			dictFormat['Valid'] = False
			dictFormat['error'] = 'Invalid FDL packet length'
		if packet.ED != 0x16:
			dictFormat['Valid'] = False
			dictFormat['error'] = "Invalid end delimiter"
		if packet.FCS != FdlSd1.calcFCS(raw(packet)[1:4]):
			dictFormat['Valid'] = False
			dictFormat['error'] = "Checksum mismatch"
		return dictFormat
	elif sd == FdlSd1.SD2:
		# Variable DU
		dictFormat['SD'] =FdlSd1.SD2
		dictFormat['LE'] =packet.LE
		dictFormat['DA'] = packet.DA
		dictFormat['SA'] = packet.SA
		dictFormat['FC']= packet.FC
		dictFormat['DSAP'] =packet.DSAP
		dictFormat['SSAP'] =packet.SSAP
		dictFormat['DU'] =packet.DU

		dictFormat['Valid'] = True
		dictFormat['error'] = ""
		le = packet.LE
		if packet.LEr != le:
			dictFormat['Valid'] = False
			dictFormat['error'] = "Repeated length field mismatch"
		if le < 3 or le > 249:
			dictFormat['Valid'] = False
			dictFormat['error'] = "Invalid LE field"			
		if packet.SDx != sd:
			dictFormat['Valid'] = False
			dictFormat['error'] = "Repeated SD mismatch"
		if packet.ED != 22:
			dictFormat['Valid'] = False
			dictFormat['error'] = "Invalid end delimiter"

		if packet.FCS != FdlSd1.calcFCS(raw(packet)[4:4+le]):
			dictFormat['Valid'] = False
			dictFormat['error'] = "Checksum mismatch"

		if len(packet.DU) != le - 5 and packet.DSAP is not None:
			dictFormat['Valid'] = False
			dictFormat['error'] = "FDL packet shorter than FE"
		if len(packet.DU) != le -3 and packet.DSAP is None:
			dictFormat['Valid'] = False
			dictFormat['error'] = "FDL packet shorter than FE"

		return dictFormat
	elif sd == FdlSd1.SD3:
		# Static 8 byte DU
		dictFormat['SD'] =FdlSd1.SD3
		dictFormat['DA'] = packet.DA
		dictFormat['SA'] = packet.SA
		dictFormat['FC']= packet.FC
		dictFormat['DU'] =packet.csDU
		dictFormat['Valid'] = True
		dictFormat['error'] = ""
		if len(packet) != 14:
			dictFormat['Valid'] = False
			dictFormat['error'] = "Invalid FDL packet length"
		if packet.ED != 0x16:
			dictFormat['Valid'] = False
			dictFormat['error'] = "Invalid end delimiter"
		if packet.FCS != FdlSd1.calcFCS(raw(packet)[1:12]):
			dictFormat['Valid'] = False
			dictFormat['error'] = "Checksum mismatch"
		return dictFormat
	elif sd == FdlSd1.SD4:
		# Token telegram
		dictFormat['SD'] =0xDC
		dictFormat['DA'] = packet.DA
		dictFormat['SA'] = packet.SA
		dictFormat['Valid'] = True
		dictFormat['error'] = ""
		if len(packet) != 4:
			dictFormat['Valid'] = False
			dictFormat['error'] = "Invalid FDL packet length"
		return dictFormat
	elif sd == FdlSd1.SC:
		# ACK
		dictFormat['SD'] = FdlSd1.SC
		dictFormat['Valid'] = True
		dictFormat['error'] = ""
		if len(packet) != 1:
			dictFormat['Valid'] = False
			dictFormat['error'] = "Invalid FDL packet length"
		return dictFormat

def dict_to_packet(dictFormat):  #dictformat to profibus scapy format 
	"""Convert from dictionary format to Scapy format"""
	if dictFormat['Valid'] is False:
		return None
	if dictFormat['SD'] == FdlSd1.SD1 and dictFormat['Valid'] is True:
		packet = FdlSd1(SD= dictFormat['SD'] ,DA=dictFormat['DA'],SA=dictFormat['SA'],FC=dictFormat['FC'])
		packetSend=FdlSd1(raw(packet))
		return packetSend
	elif dictFormat['SD']== FdlSd1.SD2 and dictFormat['Valid'] is True: 
		# Variable DU
		packet = FdlSd1(SD= dictFormat['SD'] ,DA=dictFormat['DA'],SA=dictFormat['SA'],FC=dictFormat['FC'],DSAP=dictFormat['DSAP'],SSAP=dictFormat['SSAP'],DU=dictFormat['DU'] )

		raw(packet)
		packetSend=FdlSd1(raw(packet))
		return packetSend
	elif dictFormat['SD']== FdlSd1.SD3 and dictFormat['Valid'] is True: 
		# Static 8 byte DU
		packet = FdlSd1(SD= dictFormat['SD'] ,DA=dictFormat['DA'],SA=dictFormat['SA'],FC=dictFormat['FC'],csDU=dictFormat['DU'] )
		packetSend=FdlSd1(raw(packet))
		return packetSend

	elif dictFormat['SD']== FdlSd1.SD4 and dictFormat['Valid'] is True:
		# Token telegram
		packet = FdlSd1(SD= dictFormat['SD'] ,DA=dictFormat['DA'],SA=dictFormat['SA'])
		packetSend=FdlSd1(raw(packet))
		return packetSend

	elif dictFormat['SD']== FdlSd1.SC and dictFormat['Valid'] is True:
		# ACK
		packet = FdlSd1(SD= dictFormat['SD'])
		packetSend=FdlSd1(raw(packet))
		return packetSend


class AutoTree(dict):
	"""unlimited dictionnary"""
	def __missing__(self,key):
		value = self[key] = type(self)()
		return value
class FdlError(PhyError):
	pass

     
class FdlSd1(Packet):
	""" this is profibus packet built on scapy"""
    # Start delimiter
	SD1		= 0x10	# No du
	SD2		= 0x68	# Variable DU
	SD3		= 0xA2	# 8 octet fixed DU
	SD4		= 0xDC	# Token telegram
	SC		= 0xE5	# Short ACK

	# End delimiter
	END		= 0x16

	# Addresses
	ADDRESS_MASK	= 0x7F	# Address value mask
	ADDRESS_EXT	= 0x80	# DAE/SAE present
	ADDRESS_MCAST	= 127	# Multicast/broadcast address

	# DAE/SAE (Address extension)
	AE_EXT		= 0x80	# Further extensions present
	AE_SEGMENT	= 0x40	# Segment address
	AE_ADDRESS	= 0x3F	# Address extension number

	# Frame Control
	FC_REQ		= 0x40	# Request

	# Request Frame Control function codes (FC_REQ set)
	FC_REQFUNC_MASK	= 0x0F
	FC_TIME_EV	= 0x00	# Time event
	FC_SDA_LO	= 0x03	# SDA low prio
	FC_SDN_LO	= 0x04	# SDN low prio
	FC_SDA_HI	= 0x05	# SDA high prio
	FC_SDN_HI	= 0x06	# SDN high prio
	FC_DDB		= 0x07	# Req. diagnosis data
	FC_FDL_STAT	= 0x09	# Req. FDL status
	FC_TE		= 0x0A	# Actual time event
	FC_CE		= 0x0B	# Actual counter event
	FC_SRD_LO	= 0x0C	# SRD low prio
	FC_SRD_HI	= 0x0D	# SRD high prio
	FC_IDENT	= 0x0E	# Req. ident
	FC_LSAP		= 0x0F	# Req. LSAP status

	# Frame Control Frame Count Bit (FC_REQ set)
	FC_FCV		= 0x10	# Frame Count Bit valid
	FC_FCB		= 0x20	# Frame Count Bit

	# Response Frame Control function codes (FC_REQ clear)
	FC_RESFUNC_MASK	= 0x0F
	FC_OK		= 0x00	# Positive ACK
	FC_UE		= 0x01	# User error
	FC_RR		= 0x02	# Resource error
	FC_RS		= 0x03	# No service activated
	FC_DL		= 0x08	# Res. data low
	FC_NR		= 0x09	# ACK negative
	FC_DH		= 0x0A	# Res. data high
	FC_RDL		= 0x0C	# Res. data low, resource error
	FC_RDH		= 0x0D	# Res. data high, resource error

	# Response Frame Control Station Type (FC_REQ clear)
	FC_STYPE_MASK	= 0x30
	FC_SLAVE	= 0x00	# Slave station
	FC_MNRDY	= 0x10	# Master, not ready to enter token ring
	FC_MRDY		= 0x20	# Master, ready to enter token ring
	FC_MTR		= 0x30	# Master, in token ring

	name="FDLProfibusPacketSd1"
    # Start delimiter
	fields_desc= [
	XByteEnumField("SD", 0x10, {0x10: "SD1", 0x68: "SD2" ,0xA2: "SD3" , 0xDC: "SD4", 0xE5: "SC"}),      
	#length
    ConditionalField(FieldLenField("length", None, length_of="DU"),lambda pkt: pkt.SD == 0xFF ),
	#Header1
    
    # LE  
    ConditionalField(XByteField("LE", None),lambda pkt: pkt.SD == 104 ),
    # LEr   
    ConditionalField(XByteField("LEr", None),lambda pkt: pkt.SD == 104),
	#SDx
    ConditionalField(XByteField("SDx", 0x68 ),lambda pkt: pkt.SD == 0x68 and pkt.SD!=0xa2),
	#DA
    ConditionalField(ByteField("DA",None),lambda pkt: pkt.SD != 0xE5),
	#SA
	ConditionalField(ByteField("SA",0x2),lambda pkt: pkt.SD != 0xE5),
	#FC
    ConditionalField(XByteEnumField("FC", 0x40,{ 0x40: "FC_REQ" ,	# Request 
	# Request Frame Control function codes (FC_REQ set)
	0x00: "FC_TIME_EV" ,	# Time event
	0x03: "FC_SDA_LO" ,	# SDA low prio
	0x04: "FC_SDN_LO" ,	# SDN low prio
	0x05: "FC_SDA_HI" ,	# SDA high prio
	0x06: "FC_SDN_HI" ,	# SDN high prio
	0x07: "FC_DDB" ,	# Req. diagnosis data
	0x09: "FC_FDL_STAT" ,	# Req. FDL status
	0x0A: "FC_TE" ,	# Actual time event
	0x0B: "FC_CE" ,	# Actual counter event
	0x0C: "FC_SRD_LO" ,	# SRD low prio
	0x0D: "FC_SRD_HI" ,	# SRD high prio
	0x0E: "FC_IDENT" ,	# Req. ident
	0x0F: "FC_LSAP"	, # Req. LSAP status

	# Frame Control Frame Count Bit (FC_REQ set)
	0x10: "FC_FCV" ,	# Frame Count Bit valid
	0x20: "FC_FCB" ,	# Frame Count Bit

	# Response Frame Control function codes (FC_REQ clear)
	0x00: "FC_OK" ,	# Positive ACK
	0x01: "FC_UE" ,	# User error
	0x02: "FC_RR" ,	# Resource error
	0x03: "FC_RS" ,	# No service activated
	0x08: "FC_DL" ,	# Res. data low
	0x09: "FC_NR" ,	# ACK negative
	0x0A: "FC_DH" ,	# Res. data high
	0x0C: "FC_RDL" ,	# Res. data low, resource error
	0x0D: "FC_RDH" ,	# Res. data high, resource error

	# Response Frame Control Station Type (FC_REQ clear)
	0x00: "FC_SLAVE" ,	# Slave station
	0x10: "FC_MNRDY" ,	# Master, not ready to enter token ring
	0x20: "FC_MRDY" ,	# Master, ready to enter token ring
	0x30: "FC_MTR" }),lambda pkt: pkt.SD == 0x68 or pkt.SD == 0x10 or pkt.SD == 0xA2),	# Master, in token ring

    ConditionalField(XByteField("DSAP",0xFF),lambda pkt: pkt.SD == 0x68 and pkt.DSAP is not None)  ,
		
	ConditionalField(XByteField("SSAP",0xFF),lambda pkt: pkt.SD == 0x68 and pkt.SSAP is not None),
		
    ConditionalField(XBitField("csDU",0x00, 64),lambda pkt: pkt.SD== 0xA2),   #csDU constant Data 64 bits
		
    ConditionalField(XStrLenField("DU", None,length_from = lambda pkt: pkt.LE-5 if(pkt.SSAP is not None and not pkt.DSAP & 0x40 and not pkt.SSAP & 0x40) else pkt.LE-3  ),lambda pkt: pkt.SD == 0x68 ), #not sure len= DU + (SA+DA+FC+DSAP+SSAP =5)
    	
	ConditionalField(XByteField("FCS", None),lambda pkt: pkt.SD == 0x10 or pkt.SD ==0x68 or pkt.SD == 0xA2 ),
		
	ConditionalField(XByteField("ED",0x16),lambda pkt: pkt.SD == 0x10 or pkt.SD ==0x68 or pkt.SD == 0xA2  )
	
	]

    #methods
	def do_dissect(self, s):   #dissect packet 
		flist = self.fields_desc[:]
		
		g=None
		flist.reverse()
		while s and flist:
			f = flist.pop()
			s,fval = f.getfield(self, s)
			if(f.name == "DSAP" ):
				dsap=fval
			if (getattr(self,'SD' ) == 0x68):
				if(f is not None and g is not None and g.name =="DSAP" and f.name =="SSAP" and fval is not None and dsap is not None):
					if(not dsap & 0x40 and not fval & 0x40) and (getattr(self,'DA' ) & 0x80) and (getattr(self,'SA' ) & 0x80):
						setattr(self,g.name,dsap)
						setattr(self,f.name,fval)
					else:
						s= dsap.to_bytes(1,'big') + fval.to_bytes(1,'big') + s
						setattr(self,g.name,None)
						setattr(self,f.name,None)
					
			if(f.name != "DSAP" and f.name != "SSAP" ):	
				setattr(self,f.name,fval)
			g = f 
		return s

	def post_build(self, p, pay):
	# p += pay  # if you also want the payload to be taken into account
		liste=["SD","DA","SA","FC","DSAP","SSAP","DU"]
		"""if(self.Header1 is not None):
			self.Header1 = None
			newp =self.post_build(raw(self),pay)
			print("before",newp)
			tmp = bytearray()
			#building it
			for i in range(len(newp)) :
				tmp.append(0x00)
				tmp.append(newp[i])
			header = bytearray.fromhex("a75f")		
			command = bytearray.fromhex("1501")    #NN01
			
			nbre = len(newp)

			some_bytes = nbre.to_bytes(4, 'big')
			nbre_byte = bytearray(some_bytes)

			newp =  header + command + nbre_byte + tmp
			if len(newp)%4 != 0 :		#make it 4x
				newp.append(0x00)
				newp.append(0x00)
			
			newp = bytes(newp)
			print("the end",newp)
			return newp"""
		if(self.SD == 0x10 and self.FCS is None) :
			x = sum(p[1:4])
			x=x%256
			p = p[:4] + struct.pack("!B", x)  + p[5:]  # Adds FCS
		if(self.SD == 0x68):
			tmp_len = len(p)-11 # len telegram  
			if tmp_len>244:
				warning("Broken len D : max number of bytes <=244")
			else:
				tmp_len=tmp_len+5    #not sure len= DU + SA+DA+FC+DSAP+SSAP
				x = (sum(p[4:4+tmp_len]))%256
				if(self.LE is None and self.LEr is None):
					p = p[:1] + struct.pack("!B", tmp_len) + struct.pack("!B", tmp_len)  + p[3:]  # Adds length as short on bytes 3-4
				if(self.FCS is None):
					p= p[:4+tmp_len] + struct.pack("!B", x) +p[5+tmp_len:]

			return p  # edit 
		elif(self.SD == 0xA2 and self.FCS is None):
			x = sum(p[1:12])
			x=x%256
			p = p[:12] + struct.pack("!B", x) +p[13:]
			return p
		else:
			return p
	
	@classmethod
	def getSizeFromRaw(cls, data):
		try:
			sd = data[0]
			try:
				return {
					cls.SD1	: 6,
					cls.SD3	: 14,
					cls.SD4	: 3,
					cls.SC	: 1,
				}[sd]
			except KeyError:
				pass
			if sd == cls.SD2:
				le = data[1]
				if data[2] != le:
					raise FdlError("Repeated length field mismatch")
				if le < 3 or le > 249:
					raise FdlError("Invalid LE field")
				return le + 6
			raise FdlError("Unknown start delimiter: %02X" % sd)
		except IndexError:
			raise FdlError("Invalid FDL packet format")
	######################################################################
	@staticmethod
	def calcFCS(data):
		"""calculate FCS"""
		return sum(data) & 0xFF


    #########################################################################


#tranceiver
class FdlFCB():
	"""FCB context, per slave.
	"""

	def __init__(self, enable = False):
		self.resetFCB()
		self.enableFCB(enable)

	def resetFCB(self):
		self.__fcb = 1
		self.__fcv = 0
		self.__fcbWaitingReply = False

	def enableFCB(self, enabled = True):
		self.__fcbEnabled = bool(enabled)

	def FCBnext(self):
		self.__fcb ^= 1
		self.__fcv = 1
		self.__fcbWaitingReply = False

	def enabled(self):
		return self.__fcbEnabled

	def bitIsOn(self):
		return self.__fcb != 0

	def bitIsValid(self):
		return self.__fcv != 0

	def setWaitingReply(self):
		self.__fcbWaitingReply = True

	def handleReply(self):
		if self.__fcbWaitingReply:
			self.FCBnext()

	def __repr__(self):
		return "FdlFCB(en=%s, fcb=%d, fcv=%d, wait=%s)" % (
			str(self.__fcbEnabled), self.__fcb,
			self.__fcv, str(self.__fcbWaitingReply))

from dec_profibus.layers.phy_socket import CpSockSerial
from layers.phy_pcap import CpPcap


class FdlTransceiver(object):
	"""Tranceiver over physical line"""
	def __init__(self, phy, sock_mod= True , dataBox= True , useUdp= True , usePcap = False , debug=True):
		
		if(sock_mod == True):
			self.Cpsocket = CpSockSerial(1234,Databox = dataBox , useUdp= useUdp ,debug = debug)
		self.phy = phy
		self.pcap = usePcap
		self.setRXFilter(None)
		self.sock_mod = sock_mod
		self.cpPcap = CpPcap("output_packet")

	def setRXFilter(self, newFilter):
		if newFilter is None:
			newFilter = range(0, FdlSd1.ADDRESS_MASK + 1)
		self.__rxFilter = set(newFilter)

	def __checkRXFilter(self, telegram):
		if telegram.DA is None:
			# Accept telegrams without DA field.
			return True
		# Accept the packet, if it's in the RX filter.
		return (telegram.DA & FdlSd1.ADDRESS_MASK) in self.__rxFilter

	def poll(self, timeout=0  ):
		ok, telegram = False, None
		if self.sock_mod is False :
			if self.pcap == True:
				reply = self.cpPcap.pollData()
			else:
				reply = self.phy.poll(timeout)
		else:
			reply = self.Cpsocket.pollData(timeout)


		if reply is not None:
			
			telegram = FdlSd1(reply)
			if self.__checkRXFilter(telegram):
				ok = True
		return (ok, telegram)

	# Send a FdlTelegram.
	def send(self, fcb, telegram ):
		"""Send a Profibus Telegram"""
		srd = False
		
		if telegram.FC & FdlSd1.FC_REQ:
			func = telegram.FC & FdlSd1.FC_REQFUNC_MASK
			srd = func in (FdlSd1.FC_SRD_LO,
					FdlSd1.FC_SRD_HI,
					FdlSd1.FC_SDA_LO,
					FdlSd1.FC_SDA_HI,
					FdlSd1.FC_DDB,
					FdlSd1.FC_FDL_STAT,
					FdlSd1.FC_IDENT,
					FdlSd1.FC_LSAP)
			telegram.FC &= ~(FdlSd1.FC_FCB | FdlSd1.FC_FCV)
			if fcb.enabled():
				if fcb.bitIsOn():
					telegram.FC |= FdlSd1.FC_FCB
				if fcb.bitIsValid():
					telegram.FC |= FdlSd1.FC_FCV
				if srd:
					fcb.setWaitingReply()
				else:
					fcb.FCBnext()
		if self.sock_mod is False :
			self.phy.send(telegram, srd)
		else:		
			self.Cpsocket.sendData(telegram, srd )
	# Send an FdlTelegram without fcb.
	def sendNoFcb(self,telegram):
		srd = False
		if self.sock_mod is False :
			self.phy.sendData(raw(telegram), srd)
		else:
			#self.Cpsocket.flush()
			self.Cpsocket.sendData(raw(telegram), srd )
#udp encapsulation
class FdlUdpTransceiver(object):
	def __init__(self, phy ):
		self.phy = phy
		self.setRXFilter(None)

	def setRXFilter(self, newFilter):
		if newFilter is None:
			newFilter = range(0, FdlSd1.ADDRESS_MASK + 1)
		self.__rxFilter = set(newFilter)

	def __checkRXFilter(self, telegram):
		if telegram.DA is None:
			# Accept telegrams without DA field.
			return True
		# Accept the packet, if it's in the RX filter.
		return (telegram.DA & FdlSd1.ADDRESS_MASK) in self.__rxFilter

	def poll(self, timeout=0):
		ok, telegram = False, None
		reply = self.phy.poll(timeout)
		if reply is not None:
			telegram = FdlSd1(reply)
			if self.__checkRXFilter(telegram):
				ok = True
		return (ok, telegram)

	# Send an FdlTelegram.
	def send(self, fcb, telegram):
		srd = False
		if telegram.FC & FdlSd1.FC_REQ:
			func = telegram.FC & FdlSd1.FC_REQFUNC_MASK
			srd = func in (FdlSd1.FC_SRD_LO,
				       FdlSd1.FC_SRD_HI,
				       FdlSd1.FC_SDA_LO,
				       FdlSd1.FC_SDA_HI,
				       FdlSd1.FC_DDB,
				       FdlSd1.FC_FDL_STAT,
				       FdlSd1.FC_IDENT,
				       FdlSd1.FC_LSAP)
			telegram.FC &= ~(FdlSd1.FC_FCB | FdlSd1.FC_FCV)
			if fcb.enabled():
				if fcb.bitIsOn():
					telegram.FC |= FdlSd1.FC_FCB
				if fcb.bitIsValid():
					telegram.FC |= FdlSd1.FC_FCV
				if srd:
					fcb.setWaitingReply()
				else:
					fcb.FCBnext()
		sendp(IP(src="127.0.0.1",dst="127.0.0.1")/UDP(sport=8888,dport=6789)/raw(telegram),iface="en0",count=10)
	# Send an FdlTelegram without fcb.
	def sendNoFcb(self,telegram):
		srd = False
		sendp(IP(src="127.0.0.1",dst="127.0.0.1")/UDP(sport=8888,dport=6789)/raw(telegram),iface="en0",count=10)




#default fdltelegram 

class FdlTelegram_stat0(object):
	def __new__(cls, DA, SA, FC):
		return FdlSd1(SD=FdlSd1.SD1,
		DA=DA, SA=SA, FC=FC)
	@classmethod
	def checkType(cls, telegram):
		return isinstance(telegram, cls)

class FdlTelegram_token(object):
	def __new__(cls, DA, SA):
		return FdlSd1(SD=FdlSd1.SD4,
			DA=DA, SA=SA)
	@classmethod
	def checkType(cls, telegram):
		return isinstance(telegram, cls)


class FdlTelegram_ack(object):
	def __new__(cls):
		return FdlSd1(SD=FdlSd1.SC)
	
	@classmethod
	def checkType(cls, telegram):
		return isinstance(telegram, cls)

class FdlTelegram_FdlStat_Req(FdlTelegram_stat0):
	def __new__(cls, DA, SA):
		return super().__new__(cls,DA=DA, SA=SA,
			FC=FdlSd1.FC_REQ |\
			   FdlSd1.FC_FDL_STAT)

class FdlTelegram_FdlStat_Con(FdlTelegram_stat0):
	def __new__(cls, DA, SA,
		     FC=FdlSd1.FC_OK |
		        FdlSd1.FC_SLAVE):
		return super().__new__(cls,DA=DA, SA=SA, FC=FC)

class FdlTelegram_Ident_Req(FdlTelegram_stat0):
	def __new__(cls, DA, SA):
		return super.__new__(cls,DA=DA, SA=SA,
			FC=FdlSd1.FC_REQ |\
			   FdlSd1.FC_IDENT)

class FdlTelegram_LSAp_Req(FdlTelegram_stat0):
	def __new__(cls, DA, SA):
		return super.__new__(cls,DA=DA, SA=SA,
			FC=FdlSd1.FC_REQ |\
			   FdlSd1.FC_LSAP)

class FdlTelegram_var(object):
	def __new__(cls, DA, SA, FC, dae , sae , DU):
		if(dae ==[] or sae ==[] ):
			DU=bytearray(DU)
			return FdlSd1(SD=FdlSd1.SD2,
				DA=DA, SA=SA,DSAP=None ,SSAP = None ,FC=FC, DU=bytearray(DU))
		else:
			return FdlSd1(SD=FdlSd1.SD2,
				DA=DA, SA=SA, DSAP= dae[0] , SSAP=sae[0] , FC=FC, DU=bytearray(DU))
	
	@classmethod
	def checkType(cls, telegram):
		return isinstance(telegram, cls)


class FdlTelegram_stat8(object):
	def __new__(cls, DA, SA, FC, dae, sae, DU):
		return FdlSd1(SD=FdlSd1.SD3,
			DA=DA, SA=SA, FC=FC,csDU=DU)

	@classmethod
	def checkType(cls, telegram):
		return isinstance(telegram, cls)


