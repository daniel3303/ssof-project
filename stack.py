from function import *
from variable import *

class Stack:
    def __init__(self, function):
        self.function = function

        # x86 arquicteture register.
        # By default all start with value 0
        self.registers = {
            'r14': "0x0",
            'r15': "0x0",
            'rcx': "0x0",
            'rsi': "0x0",
            'r10': "0x0",
            'rbx': "0x0",
            'rdi': "0x0",
            'r11': "0x0",
			'r8' : "0x0",
            'rdx': "0x0",
            'rip': "0x0",
            'r9' : "0x0",
	        'r12': "0x0",
            'rbp': "0x0",
            'rsp': "0x0",
            'rax': "0x0",
            'r13': "0x0"
        }

        # Variables associated to this function
        self.variables = []
        for v in self.function.getVariables():
            # Clone the variable object
            newVariable = Variable(v.getName(), v.getType(), v.getSize(), v.getAddress())

            #FIXME always relative to rbp?
            offset = newVariable.getAddress()[4:]
            executionAddress = int(self.registers["rbp"], 16) - int(offset, 16)
            newVariable.setAddress(hex(executionAddress)) 

            self.variables.append(newVariable)

        # Values on the stack
        self.values = {} # TODO init values from variables

        #Checks if the function argument is from type Function
        if not issubclass(function.__class__, Function):
            raise Error("Invalid argument. @param function must be an instace of Function.")


    def getFunction(self):
        return self.function

    def getRegisters(self):
        return self.registers

    def isRegister(self, name):
        return name in self.registers

    def setValue(self, location, value):
        # TODO check if location is in stack bounds
        if self.isRegister(location):
		    self.registers[location] = value

        elif self.isStackAddress(location):
            self.values[self.getRBPOffset(location)] = value


    def isStackAddress(self, location):
    	return isinstance(location, basestring) and "[rbp" in location

    def getRBPOffset(self, memPos):
    	return memPos[memPos.find('[rbp')+5:memPos.find(']')]

    def getValue(self, location):
        # TODO check if location is in stack bounfs
        if(self.isStackAddress(location)):
            return self.values.get(location, "0") # TODO after initializate variables remove default value

        elif(self.isRegister(location)):
            return self.registers[location]

        else:
            raise Error("This should never be executed.")

    def getVariableByAddress(self, address):
		for var in self.variables:
			print("getVariableByAddress: testing var {} == specified addr {}".format(var.address, address))
			if var.address == address:
				return var


class StackManager:
    def __init__(self):
        self.stacks = []

    def push(self, function):
        self.stacks.append(Stack(function))
        return True


    # Removes and returns the last element from the stacks lists.
    # @Return None if empty
    def pop(self):
        if len(self.stacks) < 1:
            return None

        return self.stacks.pop()

    # @Return Stack or None if empty
    def getCurrentStack(self):
        if len(self.stacks) < 1:
            return None

        return self.stacks[len(self.stacks) - 1]

    def getRegisters(self):
        return self.getCurrentStack().getRegisters()

    def isRegister(self, name):
        return self.getCurrentStack().isRegister(name)

    def setValue(self, location, value):
        self.getCurrentStack().setValue(location, value)

    def isStackAddress(self, location):
        return self.getCurrentStack().isStackAddress(location)

    def getValue(self, location):
        return self.getCurrentStack().getValue(location)

    def getVariableByAddress(self, address):
        # FIXME implement search in stacks below?
		return self.getCurrentStack().getVariableByAddress(address)
