from executer import Executer
class Function:

	def __init__(self, functionName):
		self.name = functionName
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
			if instruction.skip == False:
				instruction.accept(executer)
				instruction.executed = True 
			else:
				context.popFrame()
				return
		context.popFrame()

	def getInstructionByPos(self, pos):
		for inst in self.instructions:
			if inst.pos == pos:
				return inst

	def getInstructionByAddress(self, address):
		for inst in self.instructions:
			if inst.address == address:
				return inst

	def getUnassignedStackAddressRange(self):
		if len(self.variables) == 0: return
		#sortedVars = self.getSortedListOfVariablesByAddress()
		sortedVars = sorted(self.variables, key=lambda x: int(x.address,16), reverse=False)

		for idx, var in enumerate(sortedVars):
			nextAddress = int(var.address, 16) + var.size
			# if there exists a var after this one
			if idx < len(sortedVars)-1:
				if nextAddress == int(sortedVars[idx+1].address,16):
					continue
				else:
					# there is another variable after this
					return [nextAddress, int(sortedVars[idx+1].address,16)]
			else:
				# is last variable in list
				if nextAddress != 0:
					return [nextAddress, 0]


	# search for the first unassigned stack address after startAddress
	def getFirstUnassignedStackAddressAfterAddress(self, startAddress):
		unRange = self.getUnassignedStackAddressRange()
		if unRange != None and len(unRange) > 0:
			return unRange[0]

	def isAddressUnassignedStackAddress(self, address):
		unRange = self.getUnassignedStackAddressRange()
		if unRange != None and len(unRange) > 0:
			return int(address,16) >= unRange[0] and int(address,16) < unRange[1]


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

	def getName(self):
		return self.name
