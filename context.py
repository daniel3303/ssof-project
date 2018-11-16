from stack import *

class Context:
	def __init__(self):
		self.stack = Stack(self)

		self.functions = {}
		self.vulnerabilities = []

		# Flag for jumps, set to either 0 or 1
		self.ZF = 0

		# The starting point
		self.currentFunction = "main"

		# order of which the arguments are passed to functions in the registers
		self.argRegisterPassOrder = ['rdi','rsi','rdx','rcx','r8','r9']

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
		self.functions[self.currentFunction].execute(self)

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

	def isFunctionArgument(self,location):
		return location in self.argRegisterPassOrder

	def callFunction(self, functionName):
		# mark any variables in registers that are passed as originating from previous frame
		localVarsThatAreArgs = self.getListOfVariablesInArgumentRegisters()
		for var in localVarsThatAreArgs:
			var.ownerFrame = self.stack.getCurrentFrame()
			var.passedAsArgumentToNextFrame = True

		self.currentFunction = functionName
		self.functions[functionName].execute(self)

	# returns a list of variables that are saved in the first 6 registers
	def getListOfVariablesInArgumentRegisters(self):
		localVarsInRegisters = []
		for regName in self.argRegisterPassOrder:
			regValue = self.registers[regName]
			if self.isRegisterValueALocalVarAddress(regValue):
				localVarsInRegisters.append(self.getVariableByAddress(regValue))
		return localVarsInRegisters

	def isRegisterValueALocalVarAddress(self, address):
		for var in self.stack.getCurrentFrame().function.variables:
			if var.assemblyAddress == address:
				return True
				
	#Returns from current function
	def returnFromCurrentFunction(self):
		returningFrom = self.stack.getCurrentFunctionName()
		self.popFrame()
		
		# undo the passed asargument flag on respective variables
		curFrame = self.stack.getCurrentFrame()
		if curFrame != None:
			for var in curFrame.function.variables:
				var.passedAsArgumentToNextFrame = False
		
		self.currentFunction = returningFrom


	# is the function defined in the code by the programmer, ex: fun1, fun2...
	def isUserDefinedFunction(self, functionName):
		for function in self.functions.keys():
			if function == functionName:
				return True
		return False
