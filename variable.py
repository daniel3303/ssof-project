class Variable:
	def __init__(self, var_name, var_type, size, address):
		self.name = var_name
		self.type = var_type
		self.size = size
		self.address = address
		self.effectiveSize = size # size when simulating input, for example fgets size lower than max size