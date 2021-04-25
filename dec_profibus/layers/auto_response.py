from layers.dec_scapy import *
from layers.phy import *
from layers.DpLayer import *
from layers.UseSerial import *
from layers.phy_socket import *

monotonic_time = getattr(time, "monotonic", time.time)


def portIsUsable(portName):
    try:
       ser = serial.Serial(port=portName)
       return True
    except:
       return False


class Auto_response(CpPhy):
	"""auto response slave PROFIBUS CP PHYsical layer
	"""
	# Profibus baud-rates
	BAUD_9600	= 9600
	BAUD_19200	= 19200
	BAUD_45450	= 45450
	BAUD_93750	= 93750
	BAUD_187500	= 187500
	BAUD_500000	= 500000
	BAUD_1500000	= 1500000
	BAUD_3000000	= 3000000
	BAUD_6000000	= 6000000
	BAUD_12000000	= 12000000
	
	def __init__(self,port = None,ini_address = 0 ,useRS485Class=False, *args, **kwargs):
		self.Cpsocket = CpSockSerial(1234)
		self.debug = False
		self.counter = 1
		self.__discardTimeout = None
		self.__rxBuf = bytearray()
		self.__pollQueue = []
		self.slaveAddress = set([])
		self.slaveDAAddress = set([])
		self.masterAddress = set([])
		self.old_packet = None

		self.address = ini_address
		try:
			if useRS485Class:
				if not hasattr(serial, "rs485"):
					raise PhyError("Module serial.rs485 "
						"is not available. "
						"Please use useRS485Class=False.")
				self.__serial = serial.rs485.RS485()
			else:
				self.__serial = serial.Serial()
			self.__serial.port = port
			self.__serial.baudrate = CpPhy.BAUD_9600
			self.__serial.bytesize = 8
			self.__serial.parity = serial.PARITY_EVEN
			self.__serial.stopbits = serial.STOPBITS_ONE
			self.__serial.timeout = 0
			self.__serial.xonxoff = False
			self.__serial.rtscts = False
			self.__serial.dsrdtr = False
			if useRS485Class:
				self.__serial.rs485_mode = serial.rs485.RS485Settings(
					rts_level_for_tx = True,
					rts_level_for_rx = False,
					loopback = False,
					delay_before_tx = 0.0,
					delay_before_rx = 0.0
				)
			try:
				self.__serial.open()
			except Exception  as e:
				pass
		except (serial.SerialException, ValueError) as e:
			raise PhyError("Failed to open "
				"serial port:\n" + str(e))

	def write(self,data):
		"""writing data to the serial port"""
		try:
			self.__serial.write(data)
		except (serial.SerialException, ValueError) as e:
			raise PhyError("Failed to write data on serial port:\n" + str(e)) 

	def sockWrite(self,data ):
		"""writing data to the serial port"""
		try:
			self.Cpsocket.sendData(data , True)
		except (serial.SerialException, ValueError) as e:
			raise PhyError("Failed to write data on serial port:\n" + str(e)) 

	def __msg(self, message):
		if self.debug:
			print("CpPhyDummySlave: %s" % message)

	def __close(self):
		"""Close the PHY device.
		"""
		try:
			self.__serial.close()
		except serial.SerialException as e:
			pass
		self.__rxBuf = bytearray()
		self.__pollQueue = []

	def sendData(self, telegramData, srd):
		"""Send data to the physical line.
		"""
		if telegramData:
			if self.debug :
				self.__msg("Receiving    %s" % raw(telegramData))
			self.__mockSend(telegramData, srd = srd)

	def pollData(self, timeout = 0):
		"""Poll received data from the physical line.
		timeout => timeout in seconds.
			   0 = no timeout, return immediately.
			   negative = unlimited.
		"""
		timeoutStamp = monotonic_time() + timeout
		ret, rxBuf, s, size = None, self.__rxBuf, self.__serial, -1
		getSize = FdlSd1.getSizeFromRaw

		if self.__discardTimeout is not None:
			while self.__discardTimeout is not None:
				self.__discard()
				if timeout >= 0 and\
				   monotonic_time() >= timeoutStamp:
					return None

		try:
			while True:
				if len(rxBuf) < 1:
					rxBuf += s.read(1)
				elif len(rxBuf) < 3:
					try:
						size = getSize(rxBuf)
						readLen = size
					except PhyError:
						readLen = 3
					rxBuf += s.read(readLen - len(rxBuf))
				elif len(rxBuf) >= 3:
					try:
						size = getSize(rxBuf)
					except PhyError:
						rxBuf = bytearray()
						self.__startDiscard()
						raise PhyError("PHY-serial: "
							"Failed to get received "
							"telegram size:\n"
							"Invalid telegram format.")
					if len(rxBuf) < size:
						rxBuf += s.read(size - len(rxBuf))

				if len(rxBuf) == size:
					ret, rxBuf = rxBuf, bytearray()
					break

				if timeout >= 0 and\
				   monotonic_time() >= timeoutStamp:
					break
		except serial.SerialException as e:
			rxBuf = bytearray()
			self.__startDiscard()
			raise PhyError("PHY-serial: Failed to receive "
				"telegram:\n" + str(e))
		finally:
			self.__rxBuf = rxBuf
		if self.debug and ret:
			print("PHY-serial: RX   %s" % bytesToHex(ret))
		#
		try:
			self.__pollQueue.append(ret)   #add data to the queue
			telegramData = self.__pollQueue.pop(0)   #pop data from the queue
		except IndexError as e:
			return None	
		
		return ret
	#poll data through socket
	def sockPollData(self, timeout = 0 , useUDP = True ,DATABOX = True):

		timeoutStamp = monotonic_time() + timeout
		ret, rxBuf, s, size = None, self.__rxBuf, self.Cpsocket.socket, -1
		getSize = FdlSd1.getSizeFromRaw
		ret= s.recv(1024)

		if useUDP :
			ret = ret[13:]
			if DATABOX == True :
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


		if self.debug and ret and not useUDP:
			print("PHY-socket: RX   %s" % bytesToHex(ret))			
		return ret
	def setConfig(self, baudrate=CpPhy.BAUD_9600, *args, **kwargs):
		self.__msg("Baudrate = %d" % baudrate)
		self.__pollQueue = []
		super(Auto_response, self).setConfig(baudrate=baudrate, *args, **kwargs)

	

	def __mockSend(self, telegramData, srd ,sock_mod=True):
		"""respond to master"""
		if not srd:
			return
		try:
			fdl = FdlSd1(telegramData)
			fdl.show() 		#telegramData is the received data from master			
			response = self.chooserScapy(fdl)
			self.__msg("Sending %s  %s" % ("SRD" if srd else "SDN",
							raw(response)))	
			if sock_mod is False:
				self.write(raw(response))
			else:
				self.sockWrite(raw(response))

		except PhyError as e:
			text = "SRD mock-send error: %s" % str(e)
			self.__msg(text)
			raise PhyError(text)
	

	def __discard(self):
		s = self.__serial
		if s:
			s.flushInput()
			s.flushOutput()
		if monotonic_time() >= self.__discardTimeout:
			self.__discardTimeout = None

	def __startDiscard(self):
		self.__discardTimeout = monotonic_time() + 0.01


	def chooserScapy(self, packet):
		if (self.address == 666):					#token capture mod
			if packet.SD == 0xDC:
				packet.show()
	# detect mod 
		if (self.address == 777):					# detect mod
			if packet.DA == 0x2:
				packet.show()
		if (self.address == 888):					# spammer mod
			while True :
				fdlTelegram = FdlTelegram_FdlStat_Con(DA = 1,
									SA = 2)	
				fdlTelegram.FC = 0x20	
				self.sockWrite(raw(fdlTelegram))	
		if (self.address == 1234):
			if packet.SD == 0xDC :	#Initialization check
				if packet.SA >128 :
					self.masterAddress.add(packet.SA -128 )
				else:
					self.masterAddress.add(packet.SA )			
			if (packet.FC is not None) and (not packet.FC & 0x80 ) and (packet.FC & FdlSd1.FC_REQFUNC_MASK) == FdlSd1.FC_FDL_STAT:	#Initialization check
				if packet.SA >128 :
					self.masterAddress.add(packet.SA -128 )
				else:
					self.masterAddress.add(packet.SA )
			if packet.FC is not None:
				try:
					dp = DpTelegram.fromFdlSd1(packet, thisIsMaster = False)		#FDL to DPlayers

					if DpTelegram_SlaveDiag_Req.checkType(dp):							#Check Slave Diag
						if packet.SA >128 :
							self.masterAddress.add(packet.SA -128 )
						else:
							self.masterAddress.add(packet.SA )
					
					if DpTelegram_SET_SLAVE_ADDR.checkType(dp):							#Check Slave ADDress
						if packet.SA >128 :
							self.masterAddress.add(packet.SA -128 )
						else:
							self.masterAddress.add(packet.SA )
					
					if DpTelegram_SetPrm_Req.checkType(dp):						#Check Set Param
						if packet.SA >128 :
							self.masterAddress.add(packet.SA -128 )
						else:
							self.masterAddress.add(packet.SA )
					
					if DpTelegram_ChkCfg_Req.checkType(dp):					#Check Config
						if packet.SA >128 :
							self.masterAddress.add(packet.SA -128 )
						else:
							self.masterAddress.add(packet.SA )
					
					if DpTelegram_DataExchange_Req.checkType(dp):			#Check Data exchange
						if packet.SA >128 :
							self.masterAddress.add(packet.SA -128 )
						else:
							self.masterAddress.add(packet.SA )	
				except:
					pass
			if packet.SD == 0xe5 and self.old_packet.SA not in self.masterAddress :
				if packet.SA >128 :
					self.slaveAddress.add(packet.SA -128 )
				else:
					self.slaveAddress.add(packet.SA )
			if packet.SD == 0xe5 :
				if self.old_packet is not None and self.old_packet.DA not in self.masterAddress  and packet.DA is not None:
					if packet.DA > 128 :
						self.slaveAddress.add(packet.DA -128)
					else:
						self.slaveAddress.add(packet.DA )				
			if packet.DA not in self.masterAddress and packet.DA is not None:
				if packet.DA > 128 :
					self.slaveDAAddress.add(packet.DA -128)
				else:
					self.slaveDAAddress.add(packet.DA )
			if self.counter % 200 == 0 :
				print("Master adress ------>>>",self.masterAddress)
				print("Slave adress ------>>>",self.slaveAddress - self.masterAddress)
				print("Slave pinged but mostly none existant ------>>>",self.slaveDAAddress - self.slaveAddress )
				self.counter = 1
			self.counter = self.counter + 1
			self.old_packet = packet
		elif (packet.SD != 0xE5 and packet.SD != 0xDC):
			if packet.DA == self.address or self.address == 0:
				if (packet.FC & FdlSd1.FC_REQFUNC_MASK) == FdlSd1.FC_FDL_STAT:	#Initialization check
					fdlTelegram = FdlTelegram_FdlStat_Con(DA = packet.SA,
										SA = packet.DA)
					return fdlTelegram

				dp = DpTelegram.fromFdlSd1(packet, thisIsMaster = False)		#FDL to DPlayers
				if DpTelegram_SlaveDiag_Req.checkType(dp):							#Check Slave Diag
					dpTelegram = DpTelegram_SlaveDiag_Con(DA = packet.SA,
										SA = packet.DA)
					return dpTelegram.toFdlSd1()
				
				if DpTelegram_SET_SLAVE_ADDR.checkType(dp):							#Check Slave ADDress
					self.address = dp.newAdd
					return FdlTelegram_ack()
				
				if DpTelegram_SetPrm_Req.checkType(dp):						#Check Set Param
					return FdlTelegram_ack()
				
				if DpTelegram_ChkCfg_Req.checkType(dp):					#Check Config
					dpTelegram = FdlTelegram_ack()	
					return FdlTelegram_ack()
				
				if DpTelegram_DataExchange_Req.checkType(dp):			#Check Data exchange
					du = bytearray([ d ^ 0xFF for d in packet.DU ])
					dpTelegram = DpTelegram_DataExchange_Con(DA = packet.SA,
											SA = packet.DA,
											DU = du)
					ExTelegram=dpTelegram.toFdlSd1()				#scapy telegram
					return ExTelegram
		else:
			pass