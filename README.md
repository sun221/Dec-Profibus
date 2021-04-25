# DecProfibus

DecProfibus is a  PROFIBUS-DP stack written in Python, based on Scapy, easy to use, offers many tools.

  - Run a DP master class 1 and class 2 and a basic Slave.
  - Read and analyse PROFIBUS-DP Frames.
  - Offer simulation env based on both Socket and Serial Bus .

# New Features!

  - Compatibility with Databox Voox


You can also:
  - Scan a PROFIBUS-DP Bus.
  - Create a PROFIBUS-DP Master .
  - Create a PROFIBUS-DP Slave .
  - Extend the built-in library .

Profibus is a standard for fieldbus communication in automation technology and was first promoted in 1989 by BMBF (German department of education and research) and then used by Siemens. It should not be confused with the PROFINET standard for Industrial Ethernet. PROFIBUS is openly published as part of IEC 61158.

### Tech

DecProfibus is based on Python 3.4 or later:

* [Socat] - great tool for serial bus tests and simulations !
* [Python] - 



### Layers and Librairies

DecProfibus is currently built following many layers and libraries located in the layers folder. The order is top-bottom, every layer uses the one below it.

| Layer | File |
| ------ | ------ |
| Dpmaster Layer | master/Dpmaster.py |
| Response Layer | layer/autoresponse.py |
| DpLayer | layer/DpLayer.py |
| FDL Layer | layer/FdlLayer.py|
| Databox Layer | layer/databox_scapy.py|
| Physical socket | layer/Physock.py |
| Physical serial | layer/Physerial.py |
| Physical Layer | layer/phy.py |


#### Examples of Slave and recon tools :

DecProfibus has many options you can use , here are some of them:

##### For a standard use of a normal slave who can run through 5 Phases :

* Initialization
* Diagnostic
* Parameterization 
* Configuration
* Data Exchange 

A normal use looks like :
```sh
$ python3 slave1 no slave_addr 
```
```sh
$ python3 slave1 /dev/USBttyx slave_addr
```
PS: you should note that slave_addr is the Slave address , and "no" is for socket use i.e (no = do not use socket)
##### For a recon use :
When using socket bus :
```sh
$ python3 slave1 no option
```
Recon all slave and master addresses :
```sh
$ python3 slave1 no 666
```
capture all token exchange Frames :
```sh
$ python3 slave1 no 777
```
Spam the initialization frame  :
```sh
$ python3 slave1 no 888
```
When using Serial  :
```sh
$ python3 ./slave/slave1 /dev/USBtty1 option
```

For more options , you can always use :
```sh
$ ./slave/slave1 --help
```

##### For a standard use of a Master lvl 1/2  :
###### the conf file for master 1 is located in dec_profibus/master/conf_file1.conf :
a conf file looks like :
[PROFIBUS]
debug = 2

[PHY]
type = socket            # can be socket or serial 
dev = /dev/ttyUSB2      # if u choose socket , this parameter is not taken in account 
rtscts = False
dsrdtr = False
spibus = 0
spics = 0
spispeedhz = 2500000
baud = 19200

[FDL]

[DP]
master_class = 1
master_addr = 2
data_box = True

##### Examples of Master use :

```sh
$ python3 ./master/basic_master.py 
```
### Directories and their uses

DecProfibus is currently builded following many directories .
| Layer | Desc |
| ------ | ------ |
| socket | Contains a brodcaster to simulate a DP-Profibus  |
| gsd | Configure the slaves using gsd files |
| misc | Contains some test gsd files |
| layers | the architecture and library on which the Dp_Profibus is built on |
| master | All master executables + conf files |
| slave | Slaves with multiple lvl 0- 2 |
| tools | some misc tools |

| DpMaster | Auto_response |
| DpLayer                  |

### Layers Librairy 
#### Databox Layer
Databox Layer represents the headers added to the original Profibus_Dp Frame , To use the Databox Headers , you first have to import it :
```sh
 from dec_profibus.layers.databox_scapy import DataboxLayer  
```
Use example :
```sh
 telegramData = DataboxLayer()/FdlSd1()
```
#### Phy Layer

Phy Layer is the base layer that all other physical layers should be built on, it has many methods that must be overwrited  :
the most important ones are : 
- Close(self) : specify how the physical connexion should be closed and killed .
- pollData(timeout)   : specify how the data gonna be polled and readed from the physical bus .
- sendData : specify how the data should be sended through the physical Bus .

#### Socket Layer - Serial Layer - Pcap Layer
socket, serial, and Pcap Layers are built on the Phy Layer and overwrite all its methods  :
the most important ones are : 
- Close(self): specify how the physical connexion should be closed and killed.
- pollData(timeout): specify how the data gonna be polled and read from the physical bus.
- sendData(telegram data, srd): specify how the data should be sent through the physical Bus, telegramData is the raw data that's gonna be transmitted through the bus.
- 
#### FdlLayer Layer 
FdlLayer is divided into three parts :
- FdlSd1 packet builder .
- FdlTranseiver .
- default FdlTelegram .
##### FdlLSd1 packet builder
FdlSd1 is a Profibus-DP packet builder ,it can be used to build Profibus-DP build Raw Data or using Parameters .
 you first have to import it :
```sh
 from dec_profibus.layers.dec_scapy import FdlSd1  
```
Use example :
```sh
 telegramData = FdlSd1(SD = 0x10 , DA = 0x2 , SA = 0x1 )
 telegramData.show()
 telegramData.show2() : to build the FCS (the final packet)
 raw(telegramData)   : trandform the packet to raw data
```
Construct packet from raw Data :
```sh
 telegramData = FdlSd1( rawpacket )
 
```

##### FdlLTranseiver 
Transeiver tha can trasnmit Profibus-DP formated Data ,
- poll
- send
- sendNoFcb

##### Fdl Default Packet  
- FdlTelegram_stat0
- FdlTelegram_token
- FdlTelegram_ack
- FdlTelegram_FdlStat_Req
- FdlTelegram_FdlStat_Con
- FdlTelegram_Ident_Req
- FdlTelegram_LSAp_Req
- FdlTelegram_var
- FdlTelegram_stat8

#### DPLayer Layer 
FdlLayer is divided into two parts :
- DpTranseiver .
- default Dp Packets .

##### DpTranseiver
Transeiver tha can trasnmit Profibus-DP layer 3 formated Data ,
- poll  : polling the data from physical bus
- send : sending the data 

##### default Dp Packets 
All these packets inheret from DpTelegram which offers many useful methods like :
- fromFdlSd1 : convert a FdlLayer packet to an DpLayer packet
- getDU  : get the Data field of the packet 
- checkType : check the type of the Dplayer packet
- toFdlSd1 : convert a DPlayer packet to an FdlLayer packet

type of Dplayer packets :
- DpTelegram_DataExchange_Req  
- DpTelegram_DataExchange_Con
- DpTelegram_SlaveDiag_Req
- DpTelegram_SlaveDiag_Con
- DpTelegram_SET_SLAVE_ADDR
- DpTelegram_SetPrm_Req
- DpTelegram_ChkCfg_Req
- DpTelegram_GetCfg_Req
- DpTelegram_GetCfg_Con

#### Auto_response
Auto_response is a library that has many methods to use like chooser , it's the underlying layer of any slave ;
- chooserScapy(packet_in) : this method takes a packet as an input and give a slave packet response , the response depends on the configuration of the slave .
Use example :
```sh
  packet = fdltranseiver.poll()
  response = chooserScapy(packet)
```

### Misc tools 
Profiwrite : Interactive shell to manipulate and send profibus packets 
Spammer : Script that spam the master in order to makee it out of service
### Todo

 - Write MORE Tests 
 - Add a Pcap module
 - Improve the token exchange 

License
----

EDF R&D


**Have Fun **


 


