class Variable:
	def __init__(self, var_name, var_type, size, assemblyAddress):
		self.name = var_name
		self.type = var_type
		self.size = size
		self.address = None #Address during execution
		self.assemblyAddress = assemblyAddress #Address string on assembly (eg ebp-0x80)
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

	def getAssemblyAddress(self):
		return self.assemblyAddress

	def setAssemblyAddress(self, newAddress):
		self.assemblyAddress = newAddress
