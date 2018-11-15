#visitor pattern class
from vulnerabilities import *
from instructions import *
import re

class Executer:

	def __init__(self, context):
		self.context = context
		# helper array containing the order of how arguments are passed to functions in 64 bits
		self.argRegisterPassOrder = ['rdi','rsi','rdx','rcx','r8','r9']


	# "Overloading"
	def visit(self, instruction, context):
		print("#-- EXECUTING OPERATION: "+str(instruction.op)+" --#")
		self.context = context
		self.currentFunction = self.context.getCurrentFunction()

		if isinstance(instruction, Call):
			self.executeCall(instruction)
		elif isinstance(instruction, Cmp):
			self.executeCmp(instruction,)
		elif isinstance(instruction, Je):
			self.executeJe(instruction)
		elif isinstance(instruction, Jmp):
			self.executeJmp(instruction)
		elif isinstance(instruction, Jne):
			self.executeJne(instruction)
		elif isinstance(instruction, Lea):
			self.executeLea(instruction)
		elif isinstance(instruction, Leave):
			self.executeLeave(instruction)
		elif isinstance(instruction, Mov):
			self.executeMov(instruction)
		elif isinstance(instruction, Ret):
			self.executeRet(instruction)
		elif isinstance(instruction, Test):
			self.executeTest(instruction)

	# :::::::: execute methods ::::::::::

	def executeMov(self, instruction):
		print("executing move source: {} target: {}".format(instruction.value, instruction.dest))

		# Makes a mov operation where the value to copy is a register
		if self.context.isRegister(instruction.value):

			# Get register value
			value = self.context.getValue(instruction.value)
			self.context.setValue(instruction.dest, value)

			# Print registers (for debug)
			self.context.printRegisters()

			# Makes a mov operation where the value to copy is a value on the stack
		elif self.context.isStackAddress(instruction.value):

			# Get position value
			value = self.context.getValue(instruction.value)
			self.context.setValue(instruction.dest, value)

			# Print registers (for debug)
			self.context.printRegisters()

		# Makes a mov operation where the value to copy is a literal
		else:
			self.context.setValue(instruction.dest, instruction.value)

	def executeLea(self, instruction):
		self.context.setValue(instruction.dest, instruction.value) #FIXME is this how lea works?
		self.context.printRegisters()
		return

	def executeCall(self, instruction):
		print("executing call, instruction name: {}".format(instruction.fName))
		# num-1 characters are read, and \0 is appended, so maxDataSize is the num itself in rsi
		if "fgets" in instruction.fName: 
			maxDataSize = int(self.context.getValue("rsi"), 16)
			print("fgets max data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "fgets", instruction.address)
			destVarAddress = self.context.getValue("rdi")
			destVar = self.context.getVariableByAddress(destVarAddress)
			destVar.effectiveSize = maxDataSize
			return
		elif "gets" in instruction.fName:
			maxDataSize = 9001 # its over 9000 FIXME?
			print("data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "gets", instruction.address)
			return
		elif "strcpy" in instruction.fName:
			sourceVarAddress = self.context.getValue('rsi')
			sourceVar = self.context.getVariableByAddress(sourceVarAddress)
			maxDataSize = sourceVar.effectiveSize
			print("data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "strcpy", instruction.address)
			destVar.effectiveSize = maxDataSize
			return
		# the nullterminator of destination is overwriten by the first character of source, and the null terminator is appended at the end, so final size is sum of lens
		elif "strcat" in instruction.fName: 
			destVarAddress = self.context.getValue('rdi')
			destVar = self.context.getVariableByAddress(destVarAddress)
			sourceVarAddress = self.context.getValue('rsi')
			sourceVar = self.context.getVariableByAddress(sourceVarAddress)
			maxDataSize = destVar.effectiveSize + sourceVar.effectiveSize # appends \0 at end but first \0 is overwritten
			print("data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "strcat", instruction.address)
			destVar.effectiveSize = maxDataSize
			return
		
		elif "strncpy" in instruction.fName:
			maxSizeN = int(self.context.getValue('rdx'),16)
			sourceAddr = self.context.getValue('rsi')
			sourceVar = self.context.getVariableByAddress(sourceAddr)
			sourceVarSize = sourceVar.effectiveSize
			destAddr = self.context.getValue('rdi')
			destVar = self.context.getVariableByAddress(destAddr)
			maxDataSize = min(maxSizeN, sourceVarSize)
			print("data size {}".format(maxDataSize))
			destVar.effectiveSize = maxDataSize
			self.classifyVulnerabilities(maxDataSize, "rdi", "strncpy", instruction.address)
			destVar.effectiveSize = maxDataSize
			return
		
		elif "strncat" in instruction.fName:
			destVarAddress = self.context.getValue('rdi')
			destVar = self.context.getVariableByAddress(destVarAddress)
			sourceVarAddress = self.context.getValue('rsi')
			sourceVar = self.context.getVariableByAddress(sourceVarAddress)
			maxSizeN = int(self.context.getValue('rdx'),16)
			maxDataSize = destVar.effectiveSize + min(sourceVar.effectiveSize,maxSizeN)
			print("data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "strncat", instruction.address)
			destVar.effectiveSize = maxDataSize
			return

		##### advanced

		# TODO test read is working 
		elif "read" in instruction.fName:
			destVarAddress = self.context.getValue('rdi')
			destVar = self.context.getVariableByAddress(destVarAddress)
			maxDataSize = int(self.context.getValue('rsi'),16)
			self.classifyVulnerabilities(maxDataSize, "rdi", "read", instruction.address)
			destVar.effectiveSize = maxDataSize
			return

		elif "sprintf" in instruction.fName:
			# count % in format string, so we know which registers to check
			# TODO rsi register contains the format string and get value should return the format string
			# TODO do we consider strings only? -> %s  or consider %d , and ...
			destVarAddress = self.context.getValue('rdi')
			destVar = self.context.getVariableByAddress(destVarAddress)
			formatString = self.context.getValue('rsi')
			formatInputCount = self.countFormatStringInputsFromFormatString(formatString)
			maxDataSize = 0
			for i in range(2, formatInputCount): # skip destination and format string
				registerName = self.argRegisterPassOrder[i]
				variableAddress = self.context.getValue(registerName)
				variable = self.context.getVariableByAddress(variableAddress)
				maxDataSize += variable.effectiveSize
			self.classifyVulnerabilities(maxDataSize, "rdi", "sprintf", instruction.address)
			destVar.effectiveSize = maxDataSize
			return
		elif "scanf" in instruction.fName:
			formatString = self.context.getValue('rdi')
			formatInputCount = self.countFormatStringInputsFromFormatString(formatString)
			for i in range(1,formatInputCount): # skip format string
				registerName = self.argRegisterPassOrder[i]
				destVarAddress = self.context.getValue(registerName)
				destVar = self.context.getVariableByAddress(destVarAddress)
				dataSize = float(inf)
				self.classifyVulnerabilities(dataSize, registerName, "scanf", instruction.address)
				destVar.effectiveSize = float(inf)
			return



		# TODO CALL other functions and argument passing
		# consider direct access like a[10] = 20

	def countFormatStringInputsFromFormatString(self, formatString):
		# TODO make sure formatString is a string type from where you get it!
		if isinstance(formatString , basestring):
			registerCount = formatString.count('%s') 


	def classifyVulnerabilities(self, dataSize, destinationRegister, fname, faddress):
		self.classifyOverflowVulnerability(dataSize, destinationRegister, fname, faddress)
		self.classifyInvalidAccessVulnerability(dataSize, destinationRegister, fname, faddress)

	def classifyOverflowVulnerability(self, dataSize, destinationRegister, fname, faddress):
		destVar = self.context.getVariableByAddress(self.context.getValue(destinationRegister))
		print("destvar: "+str(destVar))
		print("destVar size {}".format(destVar.size))
		print("destVar effective size: {}".format(destVar.effectiveSize))
		if(dataSize > destVar.size): # TODO, check if works, changed from destVar.effectiveSize to destVar.size
			endOfOverflowAddress = -int(destVar.address,16) + dataSize
			print("end of overflow address = {}".format(endOfOverflowAddress))
			for variable in self.context.getVariables():
				if variable.name != destVar.name and -int(variable.address,16) < endOfOverflowAddress and -int(variable.address,16) > -int(destVar.address,16):
					vuln1 = VarOverflow(self.currentFunction.name, faddress, fname, destVar.name, variable.name)
					self.context.vulnerabilities.append(vuln1)
			if endOfOverflowAddress >= 0:
				vuln2 = RBPOverflow(self.currentFunction.name, faddress, fname, destVar.name)
				self.context.vulnerabilities.append(vuln2)
				if endOfOverflowAddress >= 4:
					vuln3= RetOverflow(self.currentFunction.name, faddress, fname, destVar.name)
					self.context.vulnerabilities.append(vuln3)


	def classifyInvalidAccessVulnerability(self, dataSize, destinationRegister, fname, faddress):
		print("-------------------Classifying invalid access:")
		destVar = self.currentFunction.getVariableByAddress(self.context.registers[destinationRegister])
		print("dataSize: {} , destVar.size {}".format(dataSize, destVar.size))

		if dataSize > destVar.size:
			endOfOverflowAddress = -int(destVar.address, 16) + dataSize
			overflowRange = [-int(destVar.address, 16), endOfOverflowAddress]
			print("overflowrange: {}".format(overflowRange))
			unAddr = self.currentFunction.getFirstUnassignedStackAddressAfterAddress(overflowRange[0]) 
			print("unassigned address first {}".format(unAddr))
			if unAddr >= overflowRange[0] and unAddr < endOfOverflowAddress:
				outAddressRelativeToRbp = "rbp"+hex(unAddr) if unAddr < 0 else "rbp+"+hex(unAddr)
				vuln1 = InvalidAccess(self.currentFunction.name, faddress, fname, destVar.name, outAddressRelativeToRbp)
				self.context.vulnerabilities.append(vuln1)

			if endOfOverflowAddress >= 16: # if writes over 0x10
				print("scorruption endOfOverflowAddress : {}".format(endOfOverflowAddress))
				# TODO , finding this address of SCORRUPTION maybe with the stack?
				vuln2 = StackCorruption(self.currentFunction.name, faddress, fname, destVar.name, "rbp+"+"0x10")
				self.context.vulnerabilities.append(vuln2)


	def executeLeave(self, instruction):
		return


	def executeRet(self, instruction):
		return


	### Advanced
	def executeCmp(self, instruction):
		return

	def executeTest(self, instruction):
		return

	def executeJe(self, instruction):
		return

	def executeJmp(self, instruction):
		return

	def executeJne(self, instruction):
		return

	## end advanced


	def getMemoryPositionSize(self, memPos):
		if(self.isMemoryPosition(memPos)):
			if "DWORD" in memPos: return 4
			if "QWORD" in memPos: return 8
		else: return 4

	def hexStringToHex(self, value):
		return int(value, 16)


	def isMemoryPosition(self, memPos):
		return isinstance(memPos, basestring) and "WORD PTR" in memPos


	def getAddressFromMemoryPositionString(self, memPos):
		return memPos[memPos.find('[rbp')+5:memPos.find(']')]
