#visitor pattern class
from vulnerabilities import *
from instructions import *
import re
from stack import *

class Executer:

	# "Overloading"
	def visit(self, instruction, context):
		print(instruction.op)
		self.context = context

		if isinstance(instruction, Add):
			self.executeAdd(instruction)
		elif isinstance(instruction, Call):
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
		elif isinstance(instruction, Push):
			self.executePush(instruction)
		elif isinstance(instruction, Ret):
			self.executeRet(instruction)
		elif isinstance(instruction, Sub):
			self.executeSub(instruction)
		elif isinstance(instruction, Test):
			self.executeTest(instruction)
		else:
			raise Exception("! EXCEPTION: Unknown instruction type visited.")
			sys.exit()


	# :::::::: execute methods ::::::::::

	def executeAdd(self, instruction):
		value = self.getValue(instruction.value);

		if(self.isRegister(instruction.dest)):
			self.context.registers[instruction.dest] += value
		if(self.isMemoryPosition(instruction.dest)):
			if self.context.stack.elementExists(instruction.dest):
				se = self.getStackElementFromMemoryPositionString(instruction.dest)
				se.content += value
				self.context.stack.updateElement(se)
			else:
				print("Error, trying to Add to non existing stack element")
				

	def executeSub(self, instruction):
		value = self.getValue(instruction.value);

		if(self.isRegister(instruction.dest)):
			self.context.registers[instruction.dest] -= value
		if(self.isMemoryPosition(instruction.dest)):
			if self.context.stack.elementExists(instruction.dest):
				se = self.getStackElementFromMemoryPositionString(instruction.dest)
				se.content -= value
				self.context.stack.updateElement(se)
			else:
				print("Error, trying to Sub to non existing stack element")

	def executeMov(self, instruction):
		value = self.getValue(instruction.value)
		
		if(self.isRegister(instruction.dest)):
			self.context.registers[instruction.dest] = value
		if(self.isMemoryPosition(instruction.dest)):
			if not self.context.stack.elementExists(instruction.dest):
				valueSize = self.getMemoryPositionSize(value)
				destAddress = self.getAddressFromMemoryPositionString(instruction.dest)
				self.context.stack.addElement(StackElement(destAddress ,valueSize, instruction.value))
			else:
				se = self.getStackElementFromMemoryPositionString(instruction.dest)
				se.content = self.getValue(instruction.value)
				self.context.stack.updateElement(se)


	def executeCmp(self, instruction):
		return
		
	def executeJe(self, instruction):
		return
		
	def executeJmp(self, instruction):
		return

	def executeJne(self, instruction):
		return

	def executeLea(self, instruction):
		return

	def executeLeave(self, instruction):
		return

	def executeNop(self, instruction):
		return

	def executePush(self, instruction):
		return

	def executeRet(self, instruction):
		return

	def executeTest(self, instruction):
		return

	def executeCall(self, instruction):
		## Check danger danger
		return

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
			if(self.isMemoryPositionRelativeToRBP(value)):
				return self.getStackElementFromMemoryPositionString(value)
			else:
				return 0x0	# we ignore anything other than rbp relative positions by just using 0

		return int(value, 16)

	def isRegister(self, string):
		return string in self.context.registers

	def isMemoryPosition(self, memPos):
		return isinstance(memPos, basestring) and "WORD PTR" in memPos

	def isMemoryPositionRelativeToRBP(self, memPos):
		return isinstance(memPos, basestring) and "[rbp" in memPos

	def getStackElementFromMemoryPositionString(self, memPos):
		print("Looking in stack for {}".format(memPos))
		if(self.isMemoryPositionRelativeToRBP(memPos)):
			value = self.getAddressFromMemoryPositionString(memPos)
			if "-" in value:
				se = self.context.stack.getElement(value[value.find('-'):])
				return se
			if "+" in value:
				se = self.context.stack.getElement(value[value.find('+'):])
				return se
		else:
			return None

	def getAddressFromMemoryPositionString(self, memPos):
		return memPos[memPos.find('[rbp')+4:memPos.find(']')]