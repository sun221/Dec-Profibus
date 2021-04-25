from scapy.all import *

class packetReader(object):

    self.file = 'file.pcap'
    def __init__(self, file):
		self.file = file
        self.list =[]

    def read():
        """read file"""
        scapy_cap = rdpcap('file.pcap')
        return scapy_cap

    def showpacket(self , type ):
        scapy_cap = self.read()

        for packet in scapy_cap :
            packet.show()
            list.append(FdlSd1(packet.Data))







