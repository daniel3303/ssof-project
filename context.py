from stack import *

class Context:
	def __init__(self):
		# TODO move register values to a stack object. The context will
		# keep a list of all the stacks and will pop one when there is a ret instruction
		self.stackManager = StackManager()

		#self.variables = {} vars globais

		self.functions = {}
		self.vulnerabilities = []

		#register values in hex
		self.registers = {'r14': "0x0", 'r15': "0x0", 'rcx': "0x0", 'rsi': "0x0",
						'r10': "0x0", 'rbx': "0x0", 'rdi': "0x0", 'r11': "0x0",
						'r8': "0x0", 'rdx': "0x0", 'rip': "0x0", 'r9': "0x0",
						'r12': "0x0", 'rbp': "0x0", 'rsp': "0x0", 'rax': "0x0", 'r13': "0x0" }

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
		for key in self.stackManager.getCurrentStackRegisters():
			print("key:{} value:{}".format(key, self.registers[key]))

	def getStackManager(self):
		return self.stackManager

	def createStack(self, function):
		return self.stackManager.createStack(function)

	def popStack(self):
		return self.stackManager.popStack()
