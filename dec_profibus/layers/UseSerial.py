import serial

class PhyError(Exception):
    """PHY exception."""

class UseSerial(object):
    """pyserial based PROFIBUS CP PHYsical layer""" 

    def __init__(self, port, useRS485Class=False, *args, **kwargs):

        try:
            if useRS485Class:
                if not hasattr(serial, "rs485"):
                    raise PhyError("Module serial.rs485 is not available. Please use useRS485Class=False.")
                self.__serial = serial.rs485.RS485()
            else:
                self.__serial = serial.Serial()
            self.__serial.port = port

            self.__serial.open()
        except (serial.SerialException, ValueError) as e:
            raise PhyError("Failed to open serial port:\n" + str(e))

    def write(self,data):
        """writing data to the serial port"""
        try:
            self.__serial.write(data)
        except (serial.SerialException, ValueError) as e:
            raise PhyError("Failed to write data on serial port:\n" + str(e)) 