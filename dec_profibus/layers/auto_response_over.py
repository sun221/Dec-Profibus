from layers.dec_scapy import *
from layers.phy import *
from layers.DpLayer import *
from layers.UseSerial import *

#Second auto response for a different slave 
monotonic_time = getattr(time, "monotonic", time.time)

def bytesToHex(b, sep = " "):
	return sep.join("%02X" % c for c in bytearray(b))

def portIsUsable(portName):
    try:
       ser = serial.Serial(port=portName)
       return True
    except:
       return False


class Auto_response(CpPhy):
	"""Auto response slave PROFIBUS CP PHYsical layer
	"""

	def __init__(self,port, useRS485Class=False, *args, **kwargs):
		self.debug = debug
		self.__discardTimeout = None
		self.__rxBuf = bytearray()
		self.__pollQueue = []
		try:
			self.__serial = serial.Serial(port=port)
		except (serial.SerialException, ValueError) as e:
			raise PhyError("Failed to open "
				"serial port:\n" + str(e))

	def write(self,data):
		"""writing data to the serial port"""
		try:
			self.__serial.write(data)
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

	def setConfig(self, baudrate=CpPhy.BAUD_9600, *args, **kwargs):
		self.__msg("Baudrate = %d" % baudrate)
		self.__pollQueue = []
		super(Auto_response, self).setConfig(baudrate=baudrate, *args, **kwargs)

	

	def __mockSend(self, telegramData, srd):
		"""respond to master"""
		if not srd:
			return
		try:
			fdl = FdlSd1(telegramData)
			fdl.show() 		#telegramData is the received data from master			
			response = self.chooserScapy(fdl)
			self.__msg("Sending %s  %s" % ("SRD" if srd else "SDN",
							raw(response)))	
			self.write(raw(response))

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

	@staticmethod
	def chooserScapy(packet):
		"""Choose the response for a given packet , offer some scanning capabilities"""
		if(packet.SD == FdlSd1.SD4 ):
			return packet
		if (packet.FC is not None and packet.FC & FdlSd1.FC_REQFUNC_MASK) == FdlSd1.FC_FDL_STAT:	#Initialization check
			fdlTelegram = FdlTelegram_FdlStat_Con(DA = packet.SA,
								SA = packet.DA)
			return fdlTelegram

		dp = DpTelegram.fromFdlSd1(packet, thisIsMaster = False)		#FDL to DPlayers
		if DpTelegram_SlaveDiag_Req.checkType(dp):							#Check Slave Diag
			dpTelegram = DpTelegram_SlaveDiag_Con(DA = packet.SA,
								SA = packet.DA)
			return dpTelegram.toFdlSd1()
		
		if DpTelegram_SET_SLAVE_ADDR.checkType(dp):							#Check Slave ADDress
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
		return None
