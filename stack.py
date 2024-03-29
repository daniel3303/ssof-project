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
	
	def removeSizeDirectives(self, address):
		return address[11:-1]

	def processAssemblyLiteral(self, value):
		# QWORD PTR [rbp+0x10]
		if self.isRelativeAddress(value) and value.find("[") > 0 and value.find("]") > 0:
			# FIXME multiplications etc...
			addressToParse = value[value.find("[")+1:value.find("]")] #eg rbp-0x50
			addressToParse = addressToParse.replace(" ", "") #remove white spaces
			address = self.convertToAbsoluteAddress(addressToParse)
			return self.getValue(address)
		
		# if not an address relative to rbp but still an address
		if "WORD PTR" in value:
			return '0x0'

		# else numeric
		return value

	# is address relative to rbp? like rbp-0x50
	def isRelativeAddress(self, location):
		return isinstance(location, str) and ("rbp-" in location or "rbp+" in location)

	def getRBPOffset(self, memPos):
		return memPos[memPos.find('[rbp')+5:memPos.find(']')]

	def getValue(self, location):
		#Some pre processing
		if location.find("[") > 0 and location.find("]") > 0:
			# FIXME multiplications etc...
			addressToGet = location[location.find("[")+1:location.find("]")] #eg rbp-0x50
			addressToGet = addressToGet.replace(" ", "") #remove white spaces
			location = addressToGet

		if(self.isRelativeAddress(location)):
			return self.getCurrentFrame().getValue(location)
		elif(self.context.isRegister(location)):
			return self.context.registers[location]

	# find variable by address, if there are variables passed by argument, find those first
	def getVariableByAddress(self, address):
		if(not self.isRelativeAddress(address)):
			address = self.convertToRelativeAddress(address)

		currentFrame = self.getCurrentFrame()
		previousFrame = self.getCurrentFrame().previousFrame
		if previousFrame != None:
			for prevVar in previousFrame.function.variables:
				# if the previous frame passed arguments to next frame(this)
				# then access that by using the relative rbp address retrieved from a register
				# and using that as a index for the previous frame's variables that were passed
				if prevVar.passedAsArgumentToNextFrame == True and "rbp"+prevVar.address in address:
					return prevVar

		return self.getCurrentFrame().getVariableByAddress(address)


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
		currentFrame = self.getCurrentFrame()
		newFrame = Frame(function)
		if currentFrame != None:
			newFrame.setPreviousFrame(currentFrame)
		self.frames.append(newFrame)

	def getCurrentFunctionName(self):
		if self.getCurrentFrame() != None:
			return self.getCurrentFrame().getFunctionName()

	def popFrame(self):
		if len(self.frames) < 1:
			return None
		return self.frames.pop()

	def getCurrentFrame(self):
		if len(self.frames) > 0:
			return self.frames[-1]
		return None

# Represents a Stack Frame
class Frame:

	def __init__(self, function):
		if not issubclass(function.__class__, Function):
			raise Exception("Invalid argument. @param function must be an instace of Function.")
		self.function = function
		self.previousFrame = None
		self.frameValues = {}

	def setPreviousFrame(self, frame):
		self.previousFrame = frame

	def getPreviousFrame(self):
		return self.previousFrame

	# given rbp+0x10 return variable at location
	def getVariableByAddress(self, address):
		for var in self.function.variables:
			if address == var.getAssemblyAddress():
				return var

	#FIXME store a copy of the variables
	def getVariables(self):
		return self.function.variables

	def getValue(self, location):
		#TODO: get value at location, then next var, etc
		if(self.function.isVariableBaseAddress(location)):
			return self.getVariableByAddress(location).getValue()
		else:
			return self.frameValues[location]

	def setValue(self, address, value):
		if(self.function.isVariableBaseAddress(address)):
			self.getVariableByAddress(address).setValue(value)
		else:
		#	'''TODO adicionar logica para tratar casos em que posicao relativa nao coincide com variavel'''
			self.frameValues[address] = value
			return

	#Store a copy of the variables and remove this
	def updateVarsAddress(self, newRBP):
		self.function.updateVarsAddress(newRBP)

	def getFunctionName(self):
		return self.function.getName()
