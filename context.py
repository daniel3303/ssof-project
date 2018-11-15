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
		registers = self.stackManager.getCurrentStackRegisters()
		for key in registers:
			print("key:{} value:{}".format(key, registers[key]))

	def getStackManager(self):
		return self.stackManager

	def createStack(self, function):
		return self.stackManager.createStack(function)

	def popStack(self):
		return self.stackManager.popStack()

	def isRegister(self, name):
		return self.stackManager.registerExistsInCurrentStack(name)

	def setValue(self, leftValue, value)
