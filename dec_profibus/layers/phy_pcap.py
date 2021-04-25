from __future__ import division, absolute_import, print_function, unicode_literals
import getopt
import sys , os
import getopt
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from layers.phy import CpPhy , PhyError
from layers.dec_scapy import FdlSd1
from util import *
from layers.databox_scapy import DataboxLayer
from scapy.all import *
from scapy.layers.inet import UDP,IP ,Ether


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


class CpPcap(CpPhy):
	"""Pcap layer
	"""

	def __init__(self,file, *args, **kwargs):

		self.__discardTimeout = None
		self.file = file
		self.liste =[]
		self.debug = False
		self.read()
		self.__rxBuf = bytearray()

	def read(self ,DATABOX =True):
		"""read file"""

		scapy_cap = rdpcap(self.file)
		ret = None
		retd = None
		for packet in scapy_cap :
			if packet.type == 2048:
				ret = packet.load
				if DATABOX == True :
					ret = ret[13:]
					#ret = bytes(ret)
					test = bytearray()
					count = 0
					for i in range(len(ret)) :
						if i%2 ==0 :
							test.append(ret[i]) 
							pass
					ret = bytes(test)
				try:
					tmp = FdlSd1(ret)
				except:
					pass
				if isinstance(tmp,FdlSd1) and hasattr(tmp,"load") and tmp.load is not None and len(tmp.load) > 6 :
					retd = FdlSd1(tmp.load)
					retd.load = None
					self.liste.append(retd)
					retd.show()
				tmp.load = None
				self.liste.append(tmp)
				tmp.show()
		
		print("done")

	def __startDiscard(self):
		self.__discardTimeout = monotonic_time() + 0.01

	# Poll for received packet.
	# timeout => In seconds. 0 = none, Negative = unlimited.
	def pollData(self, timeout = 0 ):
		"""Poll data from the socket stream"""
		ret= self.liste.pop()			#here for polling
		if self.debug :
			print("PHY-socket: RX   %s" % raw(ret))			
		return raw(ret)

	def sendData(self, telegramData, srd  ):
		"""Send data to the socket stream"""
		#TODO
	def flush(self):
		"""flush out the list , and empty it"""
		self.liste=[]

