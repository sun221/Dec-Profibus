from __future__ import division, absolute_import, print_function, unicode_literals
from dec_profibus.master.compat import *

from layers.phy import *
from layers.dec_scapy import FdlSd1
from dec_profibus.util import *

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


class CpPhySerial(CpPhy):
	"""pyserial based PROFIBUS CP PHYsical layer
	"""

	def __init__(self, port, useRS485Class=False, *args, **kwargs):
		"""port => "/dev/ttySx"
		debug => enable/disable debugging.
		useRS485Class => Use serial.rs485.RS485, if True. (might be slower).
		"""
		super(CpPhySerial, self).__init__(*args, **kwargs)
		self.__discardTimeout = None
		self.__rxBuf = bytearray()
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
			self.__serial.open()
		except (serial.SerialException, ValueError) as e:
			raise PhyError("Failed to open "
				"serial port:\n" + str(e))

	def close(self):
		try:
			self.__serial.close()
		except serial.SerialException as e:
			pass
		self.__rxBuf = bytearray()
		super(CpPhySerial, self).close()

	def __discard(self):
		s = self.__serial
		if s:
			s.flushInput()
			s.flushOutput()
		if monotonic_time() >= self.__discardTimeout:
			self.__discardTimeout = None

	def __startDiscard(self):
		self.__discardTimeout = monotonic_time() + 0.01

	# Poll for received packet.
	# timeout => In seconds. 0 = none, Negative = unlimited.
	def pollData(self, timeout = 0):
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
						print(rxBuf)
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
		return ret

	def sendData(self, telegramData, srd):
		if self.__discardTimeout is not None:
			return
		try:
			telegramData = bytearray(telegramData)
			if self.debug:
				print("PHY-serial: TX   %s" % bytesToHex(telegramData))
			self.__serial.write(telegramData)
		except serial.SerialException as e:
			raise PhyError("PHY-serial: Failed to transmit "
				"telegram:\n" + str(e))

	def setConfig(self, baudrate=CpPhy.BAUD_9600, rtscts=False, dsrdtr=False, *args, **kwargs):
		wellSuppBaud = (9600, 19200)
		if baudrate not in wellSuppBaud:
			# The hw/driver might silently ignore the baudrate
			# and use the already set value from __init__().
			print("PHY-serial: Warning: The configured baud rate %d baud "
			      "might not be supported by the hardware. "
			      "Note that some hardware silently falls back "
			      "to 9600 baud for unsupported rates. "
			      "Commonly well supported baud rates by serial "
			      "hardware are: %s." % (
			      baudrate,
			      ", ".join(str(b) for b in wellSuppBaud)))
		try:
			if baudrate != self.__serial.baudrate or rtscts != self.__serial.rtscts or dsrdtr != self.__serial.dsrdtr:
				self.__serial.close()
				self.__serial.baudrate = baudrate
				self.__serial.rtscts = rtscts
				self.__serial.dsrdtr = dsrdtr
				self.__serial.open()
				self.__rxBuf = bytearray()
		except (serial.SerialException, ValueError) as e:
			raise PhyError("Failed to set CP-PHY "
				"configuration:\n" + str(e))
		self.__setConfigPiLC(baudrate)
		super(CpPhySerial, self).setConfig(baudrate=baudrate,
						   rtscts=rtscts,
						   dsrdtr=dsrdtr,
						   *args, **kwargs)

	def __setConfigPiLC(self, baudrate):
		"""Reconfigure the PiLC HAT, if available.
		"""
		try:
			import libpilc.raspi_hat_conf as raspi_hat_conf
		except ImportError as e:
			return
		if not raspi_hat_conf.PilcConf.havePilcHat():
			return
		try:
			conf = raspi_hat_conf.PilcConf()
			conf.setBaudrate(baudrate / 1000.0)
		except raspi_hat_conf.PilcConf.Error as e:
			raise PhyError("Failed to configure PiLC HAT:\n%s" %\
				str(e))
