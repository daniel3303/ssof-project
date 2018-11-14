#visitor pattern class
from vulnerabilities import *
from instructions import *
import re

class Executer:

	# "Overloading"
	def visit(self, instruction, context):
		print(instruction.op)

		if isinstance(instruction, Add):
			self.executeAdd(instruction, context)
		elif isinstance(instruction, Call):
			self.executeCall(instruction, context)
		elif isinstance(instruction, Cmp):
			self.executeCmp(instruction, context)
		elif isinstance(instruction, Je):
			self.executeJe(instruction, context)
		elif isinstance(instruction, Jmp):
			self.executeJmp(instruction, context)
		elif isinstance(instruction, Jne):
			self.executeJne(instruction, context)
		elif isinstance(instruction, Lea):
			self.executeLea(instruction, context)
		elif isinstance(instruction, Leave):
			self.executeLeave(instruction, context)
		elif isinstance(instruction, Mov):
			self.executeMov(instruction, context)
		elif isinstance(instruction, Nop):
			self.executeNop(instruction, context)
		elif isinstance(instruction, Push):
			self.executePush(instruction, context)
		elif isinstance(instruction, Ret):
			self.executeRet(instruction, context)
		elif isinstance(instruction, Sub):
			self.executeSub(instruction, context)
		elif isinstance(instruction, Test):
			self.executeTest(instruction, context)
		else:
			raise Exception("! EXCEPTION: Unknown instruction type visited.")
			sys.exit()


	# :::::::: execute methods ::::::::::

	def executeAdd(self, instruction, context):
		if(self.isRegister(instruction.dest, context)):
			context.registers[instruction.dest] += self.getValue(instruction.value, context);
		if(self.isMemoryPosition(instruction.dest)):
			se = self.getStackElementFromMemoryPosition(instruction.dest)
			se.content += self.getValue(instruction.value)
			context.stack.updateElement(se)

	def executeSub(self, instruction, context):
		if(self.isRegister(instruction.dest, context)):
			context.registers[instruction.dest] -= self.getValue(instruction.value, context);
		if(self.isMemoryPosition(instruction.dest)):
			se = self.getStackElementFromMemoryPosition(instruction.dest)
			se.content -= self.getValue(instruction.value)
			context.stack.updateElement(se)

	def executeMov(self, instruction, context):
		# if memory position, carefull if it is rbp- or rip-, only use rbp-address, others we just set 0
		# because prolly not needed
		return



	def executeCmp(self, instruction, context):
		return
		
	def executeJe(self, instruction, context):
		return
		
	def executeJmp(self, instruction, context):
		return

	def executeJne(self, instruction, context):
		return

	def executeLea(self, instruction, context):
		return

	def executeLeave(self, instruction, context):
		return

	def executeNop(self, instruction, context):
		return

	def executePush(self, instruction, context):
		return

	def executeRet(self, instruction, context):
		return

	def executeTest(self, instruction, context):
		return

	def executeCall(self, instruction, context):
		## Check danger danger
		return

	def getMemoryPositionSize(self, memPos):
		if(self.isMemoryPosition(memPos)):
			if "DWORD" in memPos: return 4
			if "QWORD" in memPos: return 8

	def hexStringToHex(self, value):
		return int(value, 16)

	def getValue(self, value, context):
		print("Getting value from {}".format(value))

		if self.isRegister(value, context):
			return context.registers[value]

		if self.isMemoryPosition(value):
			return self.getStackElementFromMemoryPosition(value).content

		return int(value, 16)

	def isRegister(self, string, context):
		return string in context.registers

	def isMemoryPosition(self, memPos):
		return isinstance(memPos, basestring) and "WORD PTR" in memPos

	def isMemoryPositionRelativeToRBP(self, memPos):
		return isinstance(memPos, basestring) and "[rbp" in memPos

	def getStackElementFromMemoryPosition(self, memPos):
		if(self.isMemoryPositionRelativeToRBP(value)):
			inside = value[value.find('[')+1:value.find(']')]
			if "[rbp-" in value:
				return context.stack.getElement(inside[inside.find('-')+1:])
			if "[rbp+" in value:
				return context.stack.getElement(inside[inside.find('+')+1:])
		else:
			return None # ignore memory we can't track
