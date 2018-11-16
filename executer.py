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
	def visit(self, instruction):
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
		elif isinstance(instruction, Push):
			self.executePush(instruction)
		elif isinstance(instruction, Ret):
			self.executeRet(instruction)
		elif isinstance(instruction, Test):
			self.executeTest(instruction)

	# :::::::: execute methods ::::::::::

	def executeMov(self, instruction):

		# Makes a mov operation where the value to copy is a register
		if self.context.isRegister(instruction.value):
			value = self.context.getValue(instruction.value)
			self.context.setValue(instruction.dest, value)

		# Makes a mov operation where the value to copy is a value on the stack
		elif self.context.isStackAddress(instruction.value):
			value = self.context.getValue(instruction.value)
			self.context.setValue(instruction.dest, value)

		# Makes a mov operation where the value to copy is a literal
		else:
			self.context.setValue(instruction.dest, instruction.value)

		# Print registers (for debug)
		#self.context.printRegisters()





	def executeLea(self, instruction):
		# the [1:-1] removes brackets
		# because lea is an exception to bracket semantics: https://stackoverflow.com/a/25824111/7126027
		self.context.setValue(instruction.dest, instruction.value[1:-1])
		return

	def executeCall(self, instruction):
		# num-1 characters are read, and \0 is appended, so maxDataSize is the num itself in rsi
		if "fgets" in instruction.fName:
			maxDataSize = int(self.getFunctionArgumentByIndex(1), 16)
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "fgets", instruction.address)
			destVarAddress = self.getFunctionArgumentByIndex(0)
			destVar = self.context.getVariableByAddress(destVarAddress)
			destVar.effectiveSize = maxDataSize
			return
		elif "gets" in instruction.fName:
			maxDataSize = float("inf")
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "gets", instruction.address)
			return
		elif "strcpy" in instruction.fName:
			sourceVarAddress = self.getFunctionArgumentByIndex(1)
			sourceVar = self.context.getVariableByAddress(sourceVarAddress)
			maxDataSize = sourceVar.effectiveSize
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "strcpy", instruction.address)
			destVarAddress = self.getFunctionArgumentByIndex(0)
			destVar = self.context.getVariableByAddress(destVarAddress)
			destVar.effectiveSize = maxDataSize
			#self.classifyInvalidAccessVulnerability(destVar, sourceVar)
			return
		# the nullterminator of destination is overwriten by the first character of source, and the null terminator is appended at the end, so final size is sum of lens
		elif "strcat" in instruction.fName:
			destVarAddress = self.getFunctionArgumentByIndex(0)
			destVar = self.context.getVariableByAddress(destVarAddress)
			sourceVarAddress = self.getFunctionArgumentByIndex(1)
			sourceVar = self.context.getVariableByAddress(sourceVarAddress)
			maxDataSize = destVar.effectiveSize + sourceVar.effectiveSize # appends \0 at end but first \0 is overwritten
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "strcat", instruction.address)
			destVar.effectiveSize = maxDataSize
			return

		elif "strncpy" in instruction.fName:
			maxSizeN = int(self.getFunctionArgumentByIndex(2),16)
			sourceAddr = self.getFunctionArgumentByIndex(1)
			sourceVar = self.context.getVariableByAddress(sourceAddr)
			sourceVarSize = sourceVar.effectiveSize
			destAddr = self.getFunctionArgumentByIndex(0)
			destVar = self.context.getVariableByAddress(destAddr)
			maxDataSize = min(maxSizeN, sourceVarSize)
			destVar.effectiveSize = maxDataSize
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "strncpy", instruction.address)
			destVar.effectiveSize = maxDataSize
			return

		elif "strncat" in instruction.fName:
			destVarAddress = self.getFunctionArgumentByIndex(0)
			destVar = self.context.getVariableByAddress(destVarAddress)
			sourceVarAddress = self.getFunctionArgumentByIndex(1)
			sourceVar = self.context.getVariableByAddress(sourceVarAddress)
			maxSizeN = int(self.getFunctionArgumentByIndex(2),16)
			maxDataSize = destVar.effectiveSize + min(sourceVar.effectiveSize,maxSizeN)
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "strncat", instruction.address)
			destVar.effectiveSize = maxDataSize
			return

		##### advanced

		# TODO test read is working
		elif "read" in instruction.fName:
			destVarAddress = self.getFunctionArgumentByIndex(0)
			destVar = self.context.getVariableByAddress(destVarAddress)
			maxDataSize = int(self.getFunctionArgumentByIndex(1),16)
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "read", instruction.address)
			destVar.effectiveSize = maxDataSize
			return

		elif "sprintf" in instruction.fName:
			# count % in format string, so we know which registers to check
			# TODO rsi register contains the format string and get value should return the format string
			# TODO do we consider strings only? -> %s  or consider %d , and ...
			destVarAddress = self.getFunctionArgumentByIndex(0)
			destVar = self.context.getVariableByAddress(destVarAddress)
			formatString = self.getFunctionArgumentByIndex(1)
			formatInputCount = self.countFormatStringInputsFromFormatString(formatString)
			maxDataSize = 0
			for i in range(2, formatInputCount): # skip destination and format string
				variableAddress = self.getFunctionArgumentByIndex(i)
				variable = self.context.getVariableByAddress(variableAddress)
				maxDataSize += variable.effectiveSize
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "sprintf", instruction.address)
			destVar.effectiveSize = maxDataSize
			return

		elif "_scanf" in instruction.fName:
			formatString = self.getFunctionArgumentByIndex(0)
			formatInputCount = self.countFormatStringInputsFromFormatString(formatString)
			for i in range(1,formatInputCount): # skip format string
				variableAddress = self.getFunctionArgumentByIndex(i)
				destVar = self.context.getVariableByAddress(destVarAddress)
				dataSize = float(inf)
				self.classifyVulnerabilities(dataSize, self.getRegisterNameByArgIndex(i), "scanf", instruction.address)
				destVar.effectiveSize = float(inf)
			return

		elif "fscanf" in instruction.fName:
			formatString = self.getFunctionArgumentByIndex(1)
			formatInputCount = self.countFormatStringInputsFromFormatString(formatString)
			for i in range(2,formatInputCount): # skip file register and format string
				variableAddress = self.getFunctionArgumentByIndex(i)
				destVar = self.context.getVariableByAddress(destVarAddress)
				dataSize = float(inf) # file can contain "infinite" data
				self.classifyVulnerabilities(dataSize, self.getRegisterNameByArgIndex(i), "fscanf", instruction.address)
				destVar.effectiveSize = float(inf)
			return

		# TODO CALL other functions and argument passing
		# TODO ADVANCED functions here

	def executeLeave(self, instruction):
		return

	def executePush(self, instruction):
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
		return isinstance(memPos, str) and "WORD PTR" in memPos

		# TODO CALL other functions and argument passing
		# consider direct access like a[10] = 20

	def countFormatStringInputsFromFormatString(self, formatString):
		# TODO make sure formatString is a string type from where you get it!
		if isinstance(formatString , str):
			registerCount = formatString.count('%s')

	def getFunctionArgumentByIndex(self, index):
		return self.context.getValue(self.argRegisterPassOrder[index])

	def getRegisterNameByArgIndex(self, index):
		return self.argRegisterPassOrder[index]


#::::::::::::::: Generate vulnerabilities :::::::::::::::

	def classifyVulnerabilities(self, dataSize, destinationRegister, fname, faddress):
		self.classifyOverflowVulnerability(dataSize, destinationRegister, fname, faddress)
		self.classifyInvalidAccessVulnerability(dataSize, destinationRegister, fname, faddress)

	def classifyOverflowVulnerability(self, dataSize, destinationRegister, fname, faddress):
		destVar = self.context.getVariableByAddress(self.context.getValue(destinationRegister))
		if(dataSize > destVar.size): # TODO, check if works, changed from destVar.effectiveSize to destVar.size
			endOfOverflowAddress = int(destVar.address,16) + dataSize
			for variable in self.context.getVariables():
				if variable.name != destVar.name and int(variable.address,16) < endOfOverflowAddress and int(variable.address,16) > int(destVar.address,16):
					vuln1 = VarOverflow(self.currentFunction.name, faddress, fname, destVar.name, variable.name)
					self.context.vulnerabilities.append(vuln1)
			if endOfOverflowAddress >= 0:
				vuln2 = RBPOverflow(self.currentFunction.name, faddress, fname, destVar.name)
				self.context.vulnerabilities.append(vuln2)
				if endOfOverflowAddress >= 4:
					vuln3= RetOverflow(self.currentFunction.name, faddress, fname, destVar.name)
					self.context.vulnerabilities.append(vuln3)


	def classifyInvalidAccessVulnerability(self, dataSize, destinationRegister, fname, faddress):
		destVar = self.context.getVariableByAddress(self.context.getValue(destinationRegister))
		if dataSize > destVar.size:
			endOfOverflowAddress = int(destVar.address, 16) + dataSize
			overflowRange = [int(destVar.address, 16)+destVar.size, endOfOverflowAddress]
			unAddr = self.currentFunction.getFirstUnassignedStackAddressAfterAddress(overflowRange[0])
			if unAddr >= overflowRange[0] and unAddr < endOfOverflowAddress:
				outAddressRelativeToRbp = self.context.stack.convertToRelativeAddress(hex(overflowRange[0]))
				vuln1 = InvalidAccess(self.currentFunction.name, faddress, fname, destVar.name, outAddressRelativeToRbp)
				self.context.vulnerabilities.append(vuln1)

			if endOfOverflowAddress >= 16: # if writes over 0x10
				# TODO , finding this address of SCORRUPTION maybe with the stack?
				vuln2 = StackCorruption(self.currentFunction.name, faddress, fname, destVar.name, "rbp+"+"0x10")
				self.context.vulnerabilities.append(vuln2)

	#def classifyInvalidAccessVulnerability(self, destVar, sourceVar): #TODO
		#destAddr = destVar.getAssemblyAddress().replace("rbp-", "")
		#size = sourceVar.effectiveSize
		#print(int(destAddr, 16))
		#print(size)
		#if(int(destAddr, 16) <=  size):
			#print("INVALIDACCS")
