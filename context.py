from stack import *

class Context:
	def __init__(self):
		# TODO move register values to a stack object. The context will
		# keep a list of all the stacks and will pop one when there is a ret instruction
		self.stackManager = StackManager()

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
		registers = self.stackManager.getRegisters()
		for key in registers:
			print("key:{} value:{}".format(key, registers[key]))

	def getStackManager(self):
		return self.stackManager

	def push(self, function):
		return self.stackManager.push(function)

	def pop(self):
		return self.stackManager.pop()

	def isRegister(self, name):
		return self.stackManager.isRegister(name)

	def setValue(self, leftValue, value):
		self.stackManager.setValue(leftValue, value)

	def isStackAddress(self, location):
		return self.stackManager.isStackAddress(location)

	def getValue(self, location):
		return self.stackManager.getValue(location)
