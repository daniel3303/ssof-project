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
		executer = Executer(context)
		for instruction in self.instructions:
			instruction.accept(executer)

	def getVariableByAddress(self, address):
		for var in self.variables:
			print("getVariableByAddress: testing var {} == specified addr {}".format(var.address, address))
			if var.address == address: return var


	def getFirstUnassignedStackAddress(self):
		sortedVars = sorted(self.variables, key=lambda x: x.address)
		for idx, var in enumerate(sortedVars):
			# there exists a var after this one
			if idx < len(sortedVars)-1:
				nextAddress = int(var.address,16) + var.size
				if nextAddress == sortedVars[idx+1].address: 
					continue
				else:
					return nextAddress







