import getopt
import sys , os
import getopt
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from scapy.all import *
from layers.dec_scapy import *

class DataboxLayer(Packet):
    """ this is databox layer built on scapy"""
    name= "DataBoxLayer"
    # Start delimiter
    fields_desc= [
	ConditionalField(XByteField("Header1", 0xA7),lambda pkt: pkt.Header1 is not None ),	
	ConditionalField(XByteField("Header2", 0x5F),lambda pkt: pkt.Header1 == 0xA7 ),	

	ConditionalField(XByteEnumField("SPD", 0x15, {0x02: "Slow", 0x05: "Middle" ,0x10: "Fast"}), lambda pkt: pkt.Header1 == 0xA7 ),		
	ConditionalField(XByteField("FillerSp", 0x01),lambda pkt: pkt.Header1 == 0xA7 ),	
    ConditionalField(XBitField("nb carac",0x00, 32),lambda pkt: pkt.Header1 == 0xA7 )]

    def post_build(self, p, pay):
        # p += pay  # if you also want the payload to be taken into account

        newp =bytearray(pay)
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
        return newp