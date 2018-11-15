class Variable:
	def __init__(self, var_name, var_type, size, address):
		self.name = var_name
		self.type = var_type
		self.size = size
		self.address = address
		self.executionAddress = ""
		self.effectiveSize = size # size when simulating input, for example fgets size lower than max size

	def getName(self):
		return self.name;

	def getType(self):
		return self.type

	def getSize(self):
		return self.type

	def getAddress(self):
		return self.address

	def setAddress(self, newAddress):
		self.address = newAddress

	def getExecutionAddress(self):
		return self.executionAddress

	def setExecutionAddress(self, newAddress):
		self.executionAddress = newAddress
