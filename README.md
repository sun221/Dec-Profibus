# DecProfibus


[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)]()

DecProfibus is a  PROFIBUS-DP stack written in Python, based on Scapy, easy to use, offer many tools.

  - Run a DP master class 1 and class 2 and a basic Slave.
  - Read and analyse PROFIBUS-DP Frames.
  - Offers a simulation env based on both Socket and Serial Bus .

# New Features!

  - Compatibility with Databox Voox


You can also:
  - Scan a PROFIBUS-DP Bus.
  - Spam a PROFIBUS-DP Bus .
  - Extend the built-in library .

Profibus is a standard for fieldbus communication in automation technology and was first promoted in 1989 by BMBF (German department of education and research) and then used by Siemens. It should not be confused with the PROFINET standard for Industrial Ethernet. PROFIBUS is openly published as part of IEC 61158.

### Tech

DecProfibus is based on Python 3.4 or later:

* [Socat] - great tool for serial bus tests and simulations !
* [Python] - 

And DecProfibus is not yet an open source project .

### Layers and Librairies

DecProfibus is currently builded following many layers and librairies located in layers folder. The order is top bottom , every layer use the one bellow it .

| Layer | File |
| ------ | ------ |
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

A standar use looks like :
```sh
$ python3 slave1 no slave_addr 
```
```sh
$ python3 slave1 /dev/USBttyx slave_addr
```
PS: you should note that slave_addr is the Slave address , and "no" is for socket use
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

### Misc tools 
Profiwrite : Interactive shell to manipulate and send profibus packets 
Spammer : Script that spam the master in order to make hom out of service
### Todos

 - Write MORE Tests 
 - Add a Pcap module
 - Improve the token exchange 

License
----

EDF R&D


**Have Fun **

[//]: # (These are reference links used in the body of this note and get stripped out when the markdown processor does its job. There is no need to format nicely because it shouldn't be seen. Thanks SO - http://stackoverflow.com/questions/4823468/store-comments-in-markdown-syntax)


   [dill]: <https://github.com/joemccann/dillinger>
   [git-repo-url]: <https://github.com/joemccann/dillinger.git>
 


