#!/usr/bin/env python3


import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
def setTokenStart(masterList):
	masterList[0].haveToken = False
	#for i in range(1,len(masterList)):
	#	masterList[i].haveToken = False

def getTokenholder(masterList):
	for i in range(0,len(masterList)):
		if masterList[i].haveToken== True :
			count = i
			break
	return masterList[i]
def goNextToken(masterList):
	print("switching")
	"""for i in range(0,len(masterList)):
		if masterList[i].haveToken :
			count = i
			break
	masterList[i].haveToken = False
	if len(masterList) == i+1:
		masterList[i]._DpMaster__sendToMaster(masterList[0])     #need timeout config
		masterList[i].haveToken = False
		masterList[0].haveToken = True
	else:
		masterList[i]._DpMaster__sendToMaster(masterList[i+1])   #need timeout
		masterList[i].haveToken = False
		masterList[i+1].haveToken = True"""
	
	masterList[0]._DpMaster__sendToMaster(2)
	masterList[0].haveToken = False


	
master = None
import dec_profibus.master.conf
try:
	# Parse the config file.
	config = dec_profibus.PbConf.fromFile("conf_file1.conf")
	config1 = dec_profibus.PbConf.fromFile("conf_file1.conf")

	# Create a DP master.
	master = config.makeDPM()
	#master1= config1.makeDPM()
	masterList=[]
	masterList.append(master)
	#masterList.append(master1)

	# Create the slave descriptions.
	outDataList=[]
	inDataList=[]
	outData = {}
	outData1 = {}
	outDataList.append(outData)
	outDataList.append(outData1)
	inDataList.append(outData)
	inDataList.append(outData1)
	for dec_profibus.slaveConf in config.slaveConfs:
		slaveDesc = dec_profibus.slaveConf.makeDpSlaveDesc()

		# Register the slave at the DPM
		master.addSlave(slaveDesc)

		# Set initial output data.
		outDataList[0][slaveDesc.slaveAddr] = bytearray((0x42, 0x24))
	for dec_profibus.slaveConf in config1.slaveConfs:
		slaveDesc = dec_profibus.slaveConf.makeDpSlaveDesc()

		# Register the slave at the DPM
		#master1.addSlave(slaveDesc)

		# Set initial output data.
		outDataList[1][slaveDesc.slaveAddr] = bytearray((0x42, 0x24))
	# Initialize the DPM
	counter =0 
	k=0
	setTokenStart(masterList)
	print("token STAT")
	print("master 1",masterList[0].haveToken)
	#print("master 2",masterList[1].haveToken)
	print("----------------------------------------------------------------------------------------------------------------------")

	for master in masterList:
		master.initialize() 
	print("----------------------------------------------------------------------------------------------------------------------")
	
	# Run the slave state machine.
	while True:
		# Write the output data.
		if(counter == 100 ):
			if masterList[0].haveToken:
				goNextToken(masterList)
			counter =0
			pass
		for master in masterList:
			for slaveDesc in master.getSlaveList():
				if slaveDesc.slaveAddr in outDataList[masterList.index(master)].keys():
					slaveDesc.setOutData(outDataList[masterList.index(master)][slaveDesc.slaveAddr])
				else :
					outData[slaveDesc.slaveAddr] = outDataList[masterList.index(master)][126]
					slaveDesc.setOutData(outData[slaveDesc.slaveAddr])

			# Run slave state machines.
			handledSlaveDesc = master.run()

			# Get the in-data (receive)
			if handledSlaveDesc:
				inDataList[masterList.index(master)] = handledSlaveDesc.getInData()
				if inDataList[masterList.index(master)] is not None:
					# In our example the output data shall be the inverted input.
					outDataList[masterList.index(master)][handledSlaveDesc.slaveAddr][0] = inDataList[masterList.index(master)][1]
					outDataList[masterList.index(master)][handledSlaveDesc.slaveAddr][1] = inDataList[masterList.index(master)][0]
			
		if masterList[0].haveToken:
			counter += 1 
		 
except dec_profibus.PhyError as e:
	print("Terminating: %s" % str(e))
finally:
	if master:
		master.destroy()
