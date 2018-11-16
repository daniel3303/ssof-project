from stack import *

class Context:
	def __init__(self):
		self.stack = Stack(self)

		self.functions = {}
		self.vulnerabilities = []

		# The starting point
		self.currentFunction = "main"

		#Registers
		self.registers = {
			'r14': "0x0",
			'r15': "0x0",
			'rcx': "0x0",
			'rsi': "0x0",
			'r10': "0x0",
			'rbx': "0x0",
			'rdi': "0x0",
			'r11': "0x0",
			'r8' : "0x0",
			'rdx': "0x0",
			'rip': "0x0",
			'r9' : "0x0",
			'r12': "0x0",
			'rbp': "0x0",
			'rsp': "0x0",
			'rax': "0x0",
			'r13': "0x0"
		}

	def getRegisters(self):
		return self.registers

	def getRegister(self, register):
		return self.registers[register]

	def setRegister(self, register, value):
		self.registers[register] = value

	def isRegister(self, name):
		return name in self.registers

	def getCurrentFunction(self):
		return self.functions[self.currentFunction]

	def addFunction(self, function):
		self.functions[function.name] = function

	def addVulnerability(self, vulnerability):
		self.vulnerabilities.append(vulnerability)

	def execute(self):
		self.functions['main'].execute(self)

	def printRegisters(self):
		string = "Registers: "
		registers = self.getRegisters()
		for key in registers:
			print(string, end='')
			print("key:{} value:{}".format(key, registers[key]))

	def getstack(self):
		return self.stack

	def pushFrame(self, function):
		return self.stack.pushFrame(function)

	def popFrame(self):
		return self.stack.popFrame()

	def setValue(self, leftValue, value):
		self.stack.setValue(leftValue, value)

	def isStackAddress(self, location):
		return self.stack.isRelativeAddress(location)

	def getValue(self, location):
		return self.stack.getValue(location)

	def getVariables(self):
		return self.stack.getCurrentFrame().getVariables()

	def getVariableByAddress(self, address):
		return self.stack.getVariableByAddress(address)

	def getCurrentVariables(self):
		return self.functions[self.currentFunction].variables

	def isFunctionArgument(location):
		return location in ["rdi","rsi","rdx","rcx","r8","r9"]
