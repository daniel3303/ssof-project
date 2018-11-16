from function import *
from variable import *

class Stack:
	def __init__(self, context):
		self.context = context
		self.frames = []


	def setValue(self, location, value):
		value = self.processAssemblyLiteral(value)
		if self.context.isRegister(location):
			self.context.registers[location] = value
			if(location == "rbp"):
				self.getCurrentFrame().updateVarsAddress(value)
		elif self.isRelativeAddress(location):
			location = self.removeSizeDirectives(location)
			self.getCurrentFrame().setValue(location, value)
		#* TODO: endereco absoluto. op do tipo mov :
		#* else:
		#*

	def removeSizeDirectives(self, address):
		return address[11:-1]

	def processAssemblyLiteral(self, value):
		# [rbp+0x10]
		if(value[0] == "[" and value[-1:] == "]"):
			# FIXME multiplications etc...
			addressToParse = value[1:-1] #eg rbp-0x50
			addressToParse = addressToParse.replace(" ", "") #remove white spaces
			address = self.convertToAbsoluteAddress(addressToParse)
			return self.getValue(address)
		#else is address or numeric
		return value

	def isRelativeAddress(self, location):
		return isinstance(location, str) and "rbp" in location

	def getRBPOffset(self, memPos):
		return memPos[memPos.find('[rbp')+5:memPos.find(']')]

	def getValue(self, location):
		if(self.isRelativeAddress(location)):
			print("LOCALIZAÇÃO:   "+location)
			return self.getCurrentFrame().getValue(location)
		elif(self.context.isRegister(location)):
			return self.context.registers[location]

	def getVariableByAddress(self, address):
		if(not self.isRelativeAddress(address)):
			address = self.convertToRelativeAddress(address)
		return self.frames[-1].getVariableByAddress(address)

	def convertToAbsoluteAddress(self, relAddress):
		register = relAddress[0:3]
		offset = relAddress[3:]
		address = int(self.context.registers[register], 16) + int(offset, 16)
		address = hex(address)
		return address

	def convertToRelativeAddress(self, absoluteAddress):
		offset = int(absoluteAddress, 16) - int(self.context.registers["rbp"], 16)
		offset = hex(offset)
		if(offset[0] == "-"):
			return "rbp" + offset
		else:
			return "rbp+" + offset

	def pushFrame(self, function):
		self.frames.append(Frame(function))

	def popFrame(self):
		if len(self.frames) < 1:
			return None
		return self.frames.pop()

	def getCurrentFrame(self):
		return self.frames[-1]



class Frame:

	def __init__(self, function):
		if not issubclass(function.__class__, Function):
			raise Error("Invalid argument. @param function must be an instace of Function.")
		self.function = function

	# given rbp+0x10 return variable at location
	def getVariableByAddress(self, address):
		for var in self.function.variables:
			if address >= var.getAssemblyAddress() and address < var.getAssemblyAddress() + var.getSize():
				return var

	def getVariables(self):
		return self.function.variables

	def getValue(self, location):
		#TODO: get value at location, then next var, etc
		if(self.function.isVariableBaseAddress(location)):
			return self.getVariableByAddress(location).getValue()

	def setValue(self, address, value):
		if(self.function.isVariableBaseAddress(address)):
			self.getVariableByAddress(address).setValue(value)
		else:
		#	'''TODO adicionar logica para tratar casos em que posicao relativa nao coincide com variavel'''
			return

	def updateVarsAddress(self, newRBP):
		self.function.updateVarsAddress(newRBP)
