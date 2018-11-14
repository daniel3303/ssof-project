#visitor pattern class
from vulnerabilities import *
from instructions import *
import re

class Executer:

	# "Overloading"
	def visit(self, instruction, context):
		print(instruction.op)
		self.context = context
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

	def executeCall(self, instruction):
		print("executing call, instruction name: {}".format(instruction.fName))
		if "fgets" in instruction.fName:
			maxDataSize = int(self.context.registers["rsi"])
			self.classifyOverflowVulnerability(maxDataSize, "rdi", "fgets", instruction.address)
		if "gets" in instruction.fName:
			maxDataSize = 9001 # its over 9000
			print("data size {}".format(maxDataSize))
			self.classifyOverflowVulnerability(maxDataSize, "rdi", "gets", instruction.address)


	def classifyOverflowVulnerability(self, dataSize, destinationRegister, fname, faddress):
		destinationVariable = self.currentFunction.getVariableByAddress(self.context.registers[destinationRegister])
		if(dataSize > destinationVariable.size):
			endOfOverflowAddress = -int(destinationVariable.address, 16) + dataSize
			print("end of overflow address = {}".format(endOfOverflowAddress))
			for variable in self.currentFunction.variables:
				if variable.name != destinationVariable.name and variable.address > endOfOverflowAddress:
					vuln1 = VarOverflow(self.currentFunction.name, faddress, fname
						, destinationVariable.name, variable.name)
					self.context.vulnerabilities.append(vuln1)
			if endOfOverflowAddress >= 0:
				vuln2 = RBPOverflow(self.currentFunction.name,faddress, fname, destinationVariable.name)
				self.context.vulnerabilities.append(vuln2)
				if endOfOverflowAddress >= 4:
					vuln3= RetOverflow(self.currentFunction.name, faddress, fname, destinationVariable.name)
					self.context.vulnerabilities.append(vuln3)




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