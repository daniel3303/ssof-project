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
		self.variables.append(variable)

	def execute(self, context):
		# Create a stack for this function
		context.push(self)
		print("#-- STACK CREATED --#")

		executer = Executer(context)
		for instruction in self.instructions:
			instruction.accept(executer)

		# Removes the stack created at the beginning of the execution
		context.pop()
		print("#-- STACK ELIMINATED --#")

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

	def getVariables(self):
		return self.variables
