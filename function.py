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
		context.pushFrame(self)
		executer = Executer(context)
		for instruction in self.instructions:
			instruction.accept(executer)
		context.popFrame()

	def getSortedListOfVariablesByAddress(self):
		tempVarList = self.variables[:] # copy, not reference
		sortedVars = []
		numVarsSorted = 0
		while numVarsSorted < len(self.variables):
			varWithHighestAddr = tempVarList[0]
			for var2 in tempVarList:
				if var2.address >= varWithHighestAddr.address:
					varWithHighestAddr = var2

			sortedVars.append(varWithHighestAddr)
			print("added sorted Var: {}".format(varWithHighestAddr.address))
			tempVarList.remove(varWithHighestAddr)
			numVarsSorted+=1

		return sortedVars

	# search for the first unassigned stack address after startAddress
	def getFirstUnassignedStackAddressAfterAddress(self, startAddress):
		if len(self.variables) == 0: return
		print("###############getFirstUnassignedStackAddress")
		print("startAddress given: {}".format(startAddress))
		sortedVars = self.getSortedListOfVariablesByAddress()
		

		for idx, var in enumerate(sortedVars):
			# if there exists a var after this one
			if idx < len(sortedVars)-1:
				print("int var address {}, var size to add: {} ".format(var.address, var.size))
				nextAddress = -int(var.address,16) + var.size
				print("idx: {} , nextAddr: {}, varsize: {}".format(idx, nextAddress, var.size))
				if nextAddress == sortedVars[idx+1].address: 
					continue
				else:
					return nextAddress

	def getVariables(self):
		return self.variables

	def isVariableBaseAddress(self, address):
		for var in self.variables:
			if(var.address == address):
				return True
		return False

	def updateVarsAddress(self, newRBP):
		for var in self.variables:
			address = int(var.getAssemblyAddress()[3:], 16) + int(newRBP, 16)
			address = hex(address)
			var.setAddress(address)
