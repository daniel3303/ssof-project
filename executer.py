#visitor pattern class
from vulnerabilities import *
from instructions import *
import re

class Executer:

	# "Overloading"
	def visit(self, instruction, context):
		print(instruction.op)
		self.context = context
		
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
		elif isinstance(instruction, Nop):
			self.executeNop(instruction)
		elif isinstance(instruction, Ret):
			self.executeRet(instruction)
		elif isinstance(instruction, Test):
			self.executeTest(instruction)



	# :::::::: execute methods ::::::::::

	def executeMov(self, instruction):
		if self.isRegister(instruction.dest):
			if self.isRegister(instruction.value):
				self.context.registers[instruction.dest] = self.context.registers[instruction.value]
			if self.isMemoryPositionRelativeToRBP(instruction.value):
				self.context.registers[instruction.dest] = self.getAddressFromMemoryPOsitionString(instruction.value)

			# check for invalid write access here mov to unwanted position
			self.context.printRegisters()

		
	
	def executeLea(self, instruction):
		self.context.registers[instruction.dest] = self.getAddressFromMemoryPOsitionString(instruction.value)
		self.context.printRegisters()
		return

	def executeLeave(self, instruction):
		return


	def executeRet(self, instruction):
		return

	def executeNop(self, instruction):
		# empty
		return

	def executeCall(self, instruction):
		## Check danger danger
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


	def getAddressFromMemoryPOsitionString(self, memPos):
		return memPos[memPos.find('[rbp')+5:memPos.find(']')]