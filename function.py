from executer import Executer
class Function:

	def __init__(self, function_name):
		self.name = function_name
		self.instructions = []
		self.variables = []

	def addInstruction(self, instruction):
		#instruction.address = instruction.address.encode('utf-8') this causes JSON dump to fail (it does no process bytes)
		instruction.address = instruction.address
		self.instructions.append(instruction)

	def addVariable(self, variable):
		self.variables.append(variable)

	def execute(self, context):
		# Create a stack for this function
		context.pushFrame(self)
		executer = Executer(context)
		for instruction in self.instructions:
			instruction.accept(executer)
		context.popFrame()


	# search for the first unassigned stack address after startAddress
	def getFirstUnassignedStackAddressAfterAddress(self, startAddress):
		if len(self.variables) == 0: return
		#sortedVars = self.getSortedListOfVariablesByAddress()
		sortedVars = sorted(self.variables, key=lambda x: int(x.address,16), reverse=False)

		for idx, var in enumerate(sortedVars):
			# if there exists a var after this one
			if idx < len(sortedVars)-1:
				nextAddress = int(var.address,16) + var.size
				if nextAddress == int(sortedVars[idx+1].address,16):
					continue
				else:
					return nextAddress

	def getVariables(self):
		return self.variables

	def isVariableBaseAddress(self, address):
		for var in self.variables:
			if(var.assemblyAddress == address):
				return True
		return False

	def updateVarsAddress(self, newRBP):
		for var in self.variables:
			address = int(var.getAssemblyAddress()[3:], 16) + int(newRBP, 16)
			address = hex(address)
			var.setAddress(address)
