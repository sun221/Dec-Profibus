from scapy.all import *
from scapy.layers.inet import UDP,IP 
from dec_profibus.layers.databox_scapy import DataboxLayer
from dec_profibus.layers.dec_scapy import FdlSd1

class packetReader(object):
    """Packet reader"""
    def __init__(self, file):
        self.file = file
        self.list =[]

    def read(self):
        """read file"""
        scapy_cap = rdpcap(self.file)
        return scapy_cap

    def showpacket(self , type ,DATABOX = True):
        scapy_cap = self.read()

        for packet in scapy_cap :
            packet = IP(packet) 
            if DATABOX == True :
                ret = DataboxLayer(packet.load)
                ret = ret.load
                ret = ret[1:]
				#ret = bytes(ret)
                count=0
                test = bytearray()
                for i in range(len(ret)) :
                    if ret[i] != 0x00 :
                        test.append(ret[i]) 
                        pass
                    count +=1
                ret = bytes(test)
            list.append(FdlSd1(ret))







