from __future__ import division, absolute_import, print_function, unicode_literals
from dec_profibus.layers.phy import CpPhy , PhyError
import socket 
from scapy.all import *
from layers.dec_scapy import FdlSd1
from util import *
from scapy.layers.inet import UDP,IP 
from layers.databox_scapy import DataboxLayer


import sys

try:
	import serial
except ImportError as e:
	if "PyPy" in sys.version and\
	   sys.version_info[0] == 2:
		# We are on PyPy2.
		# Try to import CPython2's serial.
		import glob
		sys.path.extend(glob.glob("/usr/lib/python2*/*-packages/"))
		import serial
	else:
		raise e
try:
	import serial.rs485
except ImportError:
	pass


class CpSockSerial(CpPhy):
	"""pysocket based PROFIBUS CP PHYsical layer
	"""

	def __init__(self, port, useUdp = True, Databox = True, debug=True,*args, **kwargs):
		try:
			self.__discardTimeout = None
			self.socket = socket.socket(socket.AF_INET,  socket.SOCK_DGRAM)
			self.socket.settimeout(0.02)
			self.useUDP = useUdp
			self.Databox = Databox
			if Databox == True:
				print("try")
				self.socket.bind(('192.168.1.100', 1234))
				print("binded")
			else:
				self.socket.bind(('127.0.0.1', 1234))
			self.debug = debug
		except socket.error as e:
			print("Could not open socket: ")
			sys.exit(1)

		self.__rxBuf = bytearray()

	def close(self):
		try:
			self.socket.close()
		except serial.SerialException as e:
			pass
		self.__rxBuf = bytearray()
		self.socket.close()


	def __startDiscard(self):
		self.__discardTimeout = monotonic_time() + 0.01

	# Poll for received packet.
	# timeout => In seconds. 0 = none, Negative = unlimited.
	def pollData(self, timeout = 0 ):
		"""Poll data from the socket stream"""

		timeoutStamp = monotonic_time() + timeout

		ret, rxBuf, s, size = None, self.__rxBuf, self.socket, -1

		getSize = FdlSd1.getSizeFromRaw
		ret= s.recv(1024)
		if self.useUDP :
			ret = ret[13:]
			if self.Databox == True :
				#print(ret)
				#ret = ret.load
				#ret = ret[1:]
				#ret = bytes(ret)
				count=0
				test = bytearray()
				for i in range(len(ret)) :
					if ret[i] != 0x00 :
						test.append(ret[i]) 
						pass
					count +=1
				ret = bytes(test)
				
			



		if self.debug :
			print("PHY-socket: RX   %s" % bytesToHex(ret))			
		return ret

	def sendData(self, telegramData, srd  ):
		"""Send data to the socket stream"""
		try:
			#DATABOX ------------------------------------->
			prof_tel = telegramData
			if self.Databox == True :

				telegramData = DataboxLayer()/telegramData
				telegramData = raw(telegramData) 		#make it raw
			
			#use UDP ---------------------------------->
			if(self.useUDP == True):
				telegramData = IP(dst="192.168.1.18")/UDP(sport=1234,dport=1235)/Raw(load=telegramData)
			if self.debug:
				print("PHY-socket: TX   %s" % prof_tel )
			if self.Databox == True:		
				send(telegramData)
			else:
				self.socket.sendall(telegramData)

		except serial.SerialException as e:
			raise PhyError("PHY-socket: Failed to transmit "
				"telegram:\n" + str(e))

	def flush(self):
		"""flush out the socket , and empty its buffers"""
		while 1:
			try:
				packet = self.socket.recv(1024)
				print("flushing this",packet)
			except:
				break