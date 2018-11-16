from stack import *

class Context:
	def __init__(self):
		self.stack = Stack(self)
		#self.variables = {} vars globais
		self.functions = {}
		self.vulnerabilities = []
		# The starting point
		self.currentFunction = "main"


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
		registers = self.stack.getRegisters()
		for key in registers:
			print("key:{} value:{}".format(key, registers[key]))

	def getstack(self):
		return self.stack

	def pushFrame(self, function):
		return self.stack.pushFrame(function)

	def popFrame(self):
		return self.stack.popFrame()

	def isRegister(self, name):
		return self.stack.isRegister(name)

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
