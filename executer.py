#visitor pattern class
from vulnerabilities import *
from instructions import *
import re
import math

class Executer:
	def __init__(self, context):
		self.context = context
		# helper array containing the order of how arguments are passed to functions in 64 bits
		self.argRegisterPassOrder = ['rdi','rsi','rdx','rcx','r8','r9']

	# "Overloading"
	def visit(self, instruction):
		self.currentFunction = self.context.getCurrentFunction()
		print(instruction.op)

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
		elif isinstance(instruction, Nop):
			self.executeNop(instruction)

		#self.context.printRegisters()
		#print("\n\n")

	# :::::::: execute methods ::::::::::

	def executeMov(self, instruction):
		# Makes a mov operation where the value to copy is a register
		if self.context.isRegister(instruction.value):
			value = self.context.getValue(instruction.value)
			self.context.setValue(instruction.dest, value)

		# Makes a mov operation where the value to copy is a value on the stack
		# TODO this is broken, never is considered as stack adress, and if it is, the getValue returns None
		elif self.context.isStackAddress(instruction.value):
			rawDestAddr = instruction.value[instruction.value.find('[rbp')+1:-1]
			value = self.context.getValue(rawDestAddr)
			self.context.setValue(rawDestAddr, value)

		# Makes a mov operation where the value to copy is a literal
		else:
			self.context.setValue(instruction.dest, instruction.value)

		# TODO this is broken atm
		self.validateDirectAccess(instruction)

	# TODO not working properly, destAddr for stack corruption is always positive and invalid access not being detected
	def validateDirectAccess(self, instruction):
		if self.context.isStackAddress(instruction.dest):
			## DIRECT WRITE ACCESS
			# parse the actual address
			destAddr = instruction.dest[instruction.dest.find('[rbp')+4:-1]
			variable = self.getVariableContainingAddr(destAddr)
			if variable != None:
				if instruction.value == '0x0':
					variable.isNullTerminated = True
					variable.effectiveSize = -(int(variable.address,16) - int(destAddr,16))
				else:
					# if we're setting the last element of a variable if array to something thats not '\0'
					# then this removes the nullterminator, possibly causing overflow with strcpy for example
					if self.destinationIsLastPositionOfVariable(destAddr, variable):
						variable.isNullTerminated = False
			else:
				# addr does not belong to a variable then:
				# invalid access
				if self.destinationAddrIsUnassignedStackMemory(destAddr):
					vuln = DirectInvalidAccess(self.currentFunction.name, instruction.address, "rbp" +destAddr, instruction.op)
					self.saveVulnerability(vuln)
				# scorruption
				if int(destAddr,16) >= 16:
					vuln = DirectStackCorruption(self.currentFunction.name, instruction.address, "rbp+" + destAddr, instruction.op)
					self.saveVulnerability(vuln)


	def getVariableContainingAddr(self, addr):
		variables = self.context.getCurrentVariables()
		for var in variables:
			if int(addr,16) >= int(var.address,16) and int(addr,16) < int(var.address, 16) + var.size:
				return var
		return None

	def destinationIsLastPositionOfVariable(self, addr, variable):
		return int(addr,16) == int(variable.address, 16) + variable.size - 1

	def destinationAddrIsUnassignedStackMemory(self, addr):
		curFunction = self.context.getCurrentFunction()
		return curFunction.isAddressUnassignedStackAddress(addr)

	def executeNop(self, instruction):
		# do nothing
		return 

	def executeLea(self, instruction):
		if instruction.obs != None:
			# it is a format string then set it to the destination register instead of the address
			self.context.setValue(instruction.dest , instruction.obs)
			return

		# the [1:-1] removes brackets
		# because lea is an exception to bracket semantics: https://stackoverflow.com/a/25824111/7126027
		self.context.setValue(instruction.dest, instruction.value[1:-1])
		return

	def isUserDefinedFunction(self, fname):
		fname = fname[1:-1]
		return self.context.isUserDefinedFunction(fname)
		#return "<"+fname+">" in self.context.functions isto não funciona assim


	def executeCall(self, instruction):
		# TODO arguments are not passed properly from frame to frame
		if self.isUserDefinedFunction(instruction.fName):
			rawFunName = instruction.fName[1:-1]
			# TODO calling other funcs here
			#self.context.functions[rawFunName].execute(self.context)
			self.context.callFunction(rawFunName)

		# num-1 characters are read, and \0 is appended, so maxDataSize is the num itself in rsi
		if "fgets" in instruction.fName:
			maxDataSize = int(self.getFunctionArgumentByIndex(1), 16)
			destVarAddress = self.getFunctionArgumentByIndex(0)
			destVar = self.context.getVariableByAddress(destVarAddress)
			destVar.effectiveSize = maxDataSize
			destVar.isNullTerminated = True if destVar.effectiveSize <= destVar.size else False
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "fgets", instruction.address)
			return
		elif "gets" in instruction.fName:
			maxDataSize = float("inf")
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "gets", instruction.address)
			return
		elif "strcpy" in instruction.fName:
			sourceVarAddress = self.getFunctionArgumentByIndex(1)
			sourceVar = self.context.getVariableByAddress(sourceVarAddress)
			maxDataSize = sourceVar.effectiveSize
			destVarAddress = self.getFunctionArgumentByIndex(0)
			destVar = self.context.getVariableByAddress(destVarAddress)
			destVar.effectiveSize = maxDataSize
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "strcpy", instruction.address)
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

			# if source is longer than maxSizeN, then destination will not have a null terminate appended
			if sourceVarSize >= maxSizeN:
				destVar.isNullTerminated = False
				destVar.effectiveSize = math.inf
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(0), "strncpy", instruction.address)
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
			destVar.isNullTerminated = True
			return

		##### advanced

		elif "read" in instruction.fName:
			destVarAddress = self.getFunctionArgumentByIndex(1)
			destVar = self.context.getVariableByAddress(destVarAddress)
			maxDataSize = int(self.getFunctionArgumentByIndex(2),16)
			self.classifyVulnerabilities(maxDataSize, self.getRegisterNameByArgIndex(1), "read", instruction.address)
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

		elif "__isoc99_scanf" in instruction.fName:
			formatString = self.getFunctionArgumentByIndex(0)
			formatInputCount = self.countFormatStringInputsFromFormatString(formatString)
			for i in range(0,formatInputCount): # skip format string
				destVarAddress = self.getFunctionArgumentByIndex(i+1)
				destVar = self.context.getVariableByAddress(destVarAddress)
				dataSize = math.inf
				self.classifyVulnerabilities(dataSize, self.getRegisterNameByArgIndex(i+1), "__isoc99_scanf", instruction.address)
				destVar.effectiveSize = math.inf
			return

		elif "__isoc99_fscanf" in instruction.fName:
			formatString = self.getFunctionArgumentByIndex(1)
			formatInputCount = self.countFormatStringInputsFromFormatString(formatString)
			for i in range(0,formatInputCount): # skip file register and format string
				destVarAddress = self.getFunctionArgumentByIndex(i+2) #+2 skip file and format str
				destVar = self.context.getVariableByAddress(destVarAddress)
				dataSize = math.inf # file can contain "infinite" data
				self.classifyVulnerabilities(dataSize, self.getRegisterNameByArgIndex(i+2), "__isoc99_fscanf", instruction.address)
				destVar.effectiveSize = math.inf
			return

		# TODO CALL other functions and argument passing
		# TODO ADVANCED functions here

	def executeLeave(self, instruction):
		return

	def executePush(self, instruction):
		return

	def executeRet(self, instruction):
		self.context.returnFromCurrentFunction()
		return

	# missing some, like Nop that was deleted, was it really necessary?
	# for nop, it updates stack pointer by 4, but we dont track the stack pointer....

	def executeCmp(self, instruction):
		# are they registers or stack memory positions?
		arg0 = self.context.getValue(instruction.arg0)
		arg1 = self.context.getValue(instruction.arg1) 

		self.ZF = 1 if arg0 == arg1 else 0

	def executeTest(self, instruction):
		# are they registers or stack memory positions?
		arg0 = self.context.getValue(instruction.arg0)
		arg1 = self.context.getValue(instruction.arg1) 
		
		self.ZF = 1 if arg0 == arg1 and arg0 == 0 else 0

	def executeJmp(self, instruction):
		self.jumpToInstructionAddress(instruction, instruction.targetAddress)
		
	def executeJe(self, instruction):
		# jump if equal, ZF = 1 
		if self.context.ZF == 1:
			self.jumpToInstructionAddress(instruction, instruction.targetAddress)

	def executeJne(self, instruction):
		# jump if not equal, ZF = 0 
		if self.context.ZF == 0:
			self.jumpToInstructionAddress(instruction, instruction.targetAddress)

	def jumpToInstructionAddress(self, currentInstruction, instAddress):
		curFunc = self.context.getCurrentFunction()
		targetInst = curFunc.getInstructionByAddress(instAddress)
		self.jumpFromPosToPos(currentInstruction.pos, targetInst.pos)

	def jumpFromPosToPos(self, startPos, targetPos):
		for pos in range(startPos+1, targetPos):
			self.context.getCurrentFunction().getInstructionByPos(pos).skip = True

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
			return formatString.count('%s')

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
					self.saveVulnerability(vuln1)
			if endOfOverflowAddress > 0: # excludes endOfOVerflowAddress, border case
				vuln2 = RBPOverflow(self.currentFunction.name, faddress, fname, destVar.name)
				self.saveVulnerability(vuln2)
				if endOfOverflowAddress > 4: # excludes endOfOVerflowAddress, border case
					vuln3= RetOverflow(self.currentFunction.name, faddress, fname, destVar.name)
					self.saveVulnerability(vuln3)


	def classifyInvalidAccessVulnerability(self, dataSize, destinationRegister, fname, faddress):
		destVar = self.context.getVariableByAddress(self.context.getValue(destinationRegister))
		if dataSize > destVar.size:
			endOfOverflowAddress = int(destVar.address, 16) + dataSize
			overflowRange = [int(destVar.address, 16)+destVar.size, endOfOverflowAddress]
			unAddr = self.currentFunction.getFirstUnassignedStackAddressAfterAddress(overflowRange[0])
			if unAddr != None and unAddr >= overflowRange[0] and unAddr < endOfOverflowAddress:
				outAddressRelativeToRbp = self.context.stack.convertToRelativeAddress(hex(unAddr))
				vuln1 = InvalidAccess(self.currentFunction.name, faddress, fname, destVar.name, outAddressRelativeToRbp)
				self.saveVulnerability(vuln1)

			if endOfOverflowAddress > 16: # if writes over 0x10  # note that the position endofoverflowaddress is not overwritten, its exclusive
				# TODO , finding this address of SCORRUPTION maybe with the stack?
				vuln2 = StackCorruption(self.currentFunction.name, faddress, fname, destVar.name, "rbp+"+"0x10")
				self.saveVulnerability(vuln2)

	def saveVulnerability(self, vulnerability):
		if vulnerability not in self.context.vulnerabilities: # TODO filter duplicates? need to check later
			self.context.vulnerabilities.append(vulnerability)
