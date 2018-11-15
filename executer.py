#visitor pattern class
from vulnerabilities import *
from instructions import *
import re

class Executer:

	def __init__(self, context):
		self.context = context

	# "Overloading"
	def visit(self, instruction):
		print(instruction.op)
		self.currentFunction = self.context.functions[self.context.current_function]

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

		if self.isRegister(instruction.dest):
			if self.isRegister(instruction.value):
				print("both registers")
				self.context.registers[instruction.dest] = self.context.registers[instruction.value]
				self.context.printRegisters()
				return
			if self.isMemoryPositionRelativeToRBP(instruction.value):
				print("mem position")
				self.context.registers[instruction.dest] = self.getAddressFromMemoryPositionString(instruction.value)
				self.context.printRegisters()
				return

			self.context.registers[instruction.dest] = instruction.value

			# check for invalid write access here mov to unwanted position

		
	
	def executeLea(self, instruction):
		self.context.registers[instruction.dest] = self.getAddressFromMemoryPositionString(instruction.value)
		self.context.printRegisters()
		return

	# TODO clean code
	def executeCall(self, instruction):
		print("executing call, instruction name: {}".format(instruction.fName))
		if "fgets" in instruction.fName:
			maxDataSize = int(self.context.registers["rsi"],16)
			print("fgets max data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "fgets", instruction.address)
			destVarAddress = self.context.registers["rdi"]
			destVar = self.currentFunction.getVariableByAddress(destVarAddress)
			destVar.effectiveSize = maxDataSize 
			return
		if "gets" in instruction.fName:
			maxDataSize = 9001 # its over 9000
			print("data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "gets", instruction.address)
			return
		if "strcpy" in instruction.fName:
			sourceVarAddress = self.context.registers['rsi']
			sourceVar = self.currentFunction.getVariableByAddress(sourceVarAddress)
			maxDataSize = sourceVar.effectiveSize
			print("data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "strcpy", instruction.address)
			return
		if "strcat" in instruction.fName:
			destVarAddress = self.context.registers['rdi']
			destVar = self.currentFunction.getVariableByAddress(destVarAddress)
			sourceVarAddress = self.context.registers['rsi']
			sourceVar = self.currentFunction.getVariableByAddress(sourceVarAddress)
			maxDataSize = destVar.effectiveSize + sourceVar.effectiveSize # appends \0 at end but first \0 is overwritten
			print("data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "strcat", instruction.address)
			return
		if "strncpy" in instruction.fName:
			maxSizeN = int(self.context.registers['rdx'],16)
			sourceAddr = self.context.registers['rsi']
			sourceVar = self.currentFunction.getVariableByAddress(sourceAddr)
			sourceVarSize = sourceVar.effectiveSize
			destAddr = self.context.registers['rdi']
			destVar = self.currentFunction.getVariableByAddress(destAddr)
			maxDataSize = min(maxSizeN, sourceVarSize)
			print("data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "strncpy", instruction.address)
			return
		if "strncat" in instruction.fName:
			destVarAddress = self.context.registers['rdi']
			destVar = self.currentFunction.getVariableByAddress(destVarAddress)
			sourceVarAddress = self.context.registers['rsi']
			sourceVar = self.currentFunction.getVariableByAddress(sourceVarAddress)
			maxSizeN = int(self.context.registers['rdx'],16)
			maxDataSize = destVar.effectiveSize + min(sourceVar.effectiveSize,maxSizeN) 
			print("data size {}".format(maxDataSize))
			self.classifyVulnerabilities(maxDataSize, "rdi", "strncat", instruction.address)
			return	

		# TODO CALL other functions and argument passing
		# TODO ADVANCED functions here
	
	def classifyVulnerabilities(self, dataSize, destinationRegister, fname, faddress):
		self.classifyOverflowVulnerability(dataSize, destinationRegister, fname, faddress)
		self.classifyInvalidAccessVulnerability(dataSize, destinationRegister, fname, faddress)

	def classifyOverflowVulnerability(self, dataSize, destinationRegister, fname, faddress):
		destVar = self.currentFunction.getVariableByAddress(self.context.registers[destinationRegister])
		print("destVar size {}".format(destVar.size))
		print("destVar effective size: {}".format(destVar.effectiveSize))
		if(dataSize > destVar.effectiveSize):
			endOfOverflowAddress = -int(destVar.address,16) + dataSize
			print("end of overflow address = {}".format(endOfOverflowAddress))
			for variable in self.currentFunction.variables:
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
		destVar = self.currentFunction.getVariableByAddress(self.context.registers[destinationRegister])
		if dataSize > destVar.size:
			endOfOverflowAddress = -int(destVar.address, 16) + dataSize
			overflowRange = [-int(destVar.address, 16), endOfOverflowAddress]
			unAddr = self.currentFunction.getFirstUnassignedStackAddress()
			if unAddr >= overflowRange[0] and unAddr < endOfOverflowAddress:
				vuln1 = InvalidAccess(self.currentFunction.name, faddress, fname, destVar.name, hex(unAddr))
				self.context.vulnerabilities.append(vuln1)

			if endOfOverflowAddress > 8:
				vuln2 = StackCorruption(self.currentFunction.name, faddress, fname, destVar.name, hex(endOfOverflowAddress))
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

	def getValue(self, value):
		if value == None:
			return None

		if self.isRegister(value):
			return self.context.registers[value]

		if self.isMemoryPosition(value):
			return self.getAddressFromMemoryPOsitionString(value)

		return int(value, 16)

	def isRegister(self, string):
		return string in self.context.registers

	def isMemoryPosition(self, memPos):
		return isinstance(memPos, basestring) and "WORD PTR" in memPos

	def isMemoryPositionRelativeToRBP(self, memPos):
		return isinstance(memPos, basestring) and "[rbp" in memPos


	def getAddressFromMemoryPositionString(self, memPos):
		return memPos[memPos.find('[rbp')+5:memPos.find(']')]