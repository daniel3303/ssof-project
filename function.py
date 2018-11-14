from executer import Executer
from stack import *

class Function:
	
	def __init__(self, function_name):
		self.name = function_name
		self.instructions = []
		self.variables = []
		self.stack = Stack() 

	def addInstruction(self, instruction):
		instruction.address = int(instruction.address.encode('utf-8'),16)
		self.instructions.append(instruction)

	def addVariable(self, variable):
		variable.address = int(variable.address.encode('utf-8')[3:],16)
		self.variables.append(variable)
		stackElement = StackElement(variable.address, variable.size, "")
		self.stack.addElement(stackElement)

	def execute(self, context):
		for instruction in self.instructions:
			instruction.accept(Executer(), context)


