from executer import Executer
class Function:
	
	def __init__(self, function_name):
		self.name = function_name
		self.instructions = []
		self.variables = []

	def addInstruction(self, instruction):
		instruction.address = instruction.address.encode('utf-8')
		self.instructions.append(instruction)

	def addVariable(self, variable):
		variable.address = variable.address.encode('utf-8')[4:]
		self.variables.append(variable)

	def execute(self, context):
		for instruction in self.instructions:
			instruction.accept(Executer(), context)

	def getVariableByAddress(self, address):
		for var in self.variables:
			if var.address == address: return var


