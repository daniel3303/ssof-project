#Class representing a function variable/parameter
class Variable:
	def __init__(self, var_name, var_type, size, assemblyAddress):
		self.name = var_name
		self.type = var_type
		self.size = size
		self.address = "" #Address during execution
		self.assemblyAddress = assemblyAddress #Address string on assembly (eg ebp-0x80)
		self.effectiveSize = size # size when simulating input, for example fgets size lower than max size
		self.value = ""
		# in case the variable is a string
		self.isNullTerminated = True
		# the owner frame is just the frame / function that owns the local variable
		self.ownerFrame = None
		# when we access a variable from a previous frame, make sure it was passed in
		self.passedAsArgumentToNextFrame = False

	#Some getters and setters
	def getName(self):
		return self.name

	def getType(self):
		return self.type

	def getSize(self):
		return self.type

	def getAddress(self):
		return self.address

	def setAddress(self, newAddress):
		self.address = newAddress

	# assembly address is something similar to DWORD PTR [reg-addr]
	def getAssemblyAddress(self):
		return self.assemblyAddress

	def setAssemblyAddress(self, newAddress):
		self.assemblyAddress = newAddress

	def setValue(self, value):
		self.effectiveSize = len(value)
		self.value = value

	def getValue(self):
		return self.value
