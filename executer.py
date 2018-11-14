#visitor pattern class
from vulnerabilities import *
from instructions import *

class Executer:

	# "Overloading"
	def visit(self, instruction, context):
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
		print(instruction.op)
		#value = self.isMemoryPosition(instruction.value) 
		#		?? context.stack.getElement(hexStringToHex(value)) : instruction.value;

	def executeSub(self, instruction, context):
		print(instruction.op)

	def executeMov(self, instruction, context):
		print(instruction.op)

	def executeCall(self, instruction, context):
		print(instruction.op)

	def executeCmp(self, instruction, context):
		print(instruction.op)
		
	def executeJe(self, instruction, context):
		print(instruction.op)
		
	def executeJmp(self, instruction, context):
		print(instruction.op)

	def executeJne(self, instruction, context):
		print(instruction.op)

	def executeLea(self, instruction, context):
		print(instruction.op)

	def executeLeave(self, instruction, context):
		print(instruction.op)

	def executeNop(self, instruction, context):
		print(instruction.op)

	def executePush(self, instruction, context):
		print(instruction.op)

	def executeRet(self, instruction, context):
		print(instruction.op)

	def executeTest(self, instruction, context):
		print(instruction.op)

	def isMemoryPosition(self, memPos):
		return isinstance(memPos, basestring) and "WORD PTR" in memPos

	def getMemoryPositionSize(self, memPos):
		if(self.isMemoryPosition(memPos)):
			if "DWORD" in memPos: return 4
			if "QWORD" in memPos: return 8

	def hexStringToHex(self, value):
		return hex(int(value),16)

	