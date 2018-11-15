from function import *
from variable import *

class Stack:
    def __init__(self, function):
        self.function = function

        # x86 arquicteture register.
        # By default all start with value 0
        #FIXME copy registers from previous stack
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
            newVariable = Variable(v.getName(), v.getType(), v.getSize(), v.getAssemblyAddress())
            offset = newVariable.getAssemblyAddress()[4:]
            address = int(self.registers["rbp"], 16) - int(offset, 16)
            newVariable.setAddress(hex(address))

            self.variables.append(newVariable)
            print("VARIABLE: "+newVariable.getName() + "\nADDRESS: "+newVariable.getAddress()+"\n")

        # Values on the stack
        self.values = {} # TODO init values from variables

        #Checks if the function argument is from type Function
        if not issubclass(function.__class__, Function):
            raise Error("Invalid argument. @param function must be an instace of Function.")


    def getFunction(self):
        return self.function

    def getRegisters(self):
        return self.registers

    def setRegisters(self, newRegisters):
        self.registers = newRegisters

    def isRegister(self, name):
        return name in self.registers

    def setValue(self, location, value):
        # TODO check if location is in stack bounds

        # Process values
        value = self.processAssemblyLiteral(value)

        if self.isRegister(location):
		    self.registers[location] = value

        elif self.isStackAddress(location):
            self.values[self.getRBPOffset(location)] = value

    def processAssemblyLiteral(self, value):
        if(value[0] == "[" and value[-1:] == "]"):
            # FIXME multiplications etc...
    		valueToParse = value[1:-1] #eg rbp-0x50
    		valueToParse = valueToParse.replace(" ", "") #remove white spaces
    		register = valueToParse[0:3]
    		operation = valueToParse[3:4]
    		offset = valueToParse[4:]

    		if(operation == "+"):
    			value = int(self.registers[register], 16) + int(offset, 16)
    		else:
    			value = int(self.registers[register], 16) - int(offset, 16)

    		value = hex(value)

        return value

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
			if var.getAddress() == address:
				return var

    def getVariables(self):
        return self.variables


class StackManager:
    def __init__(self):
        self.stacks = []

    def push(self, function):
        newStack = Stack(function)
        currentStack = self.getCurrentStack()

        # When a new stack is pushed copy the old registers
        if currentStack is not None:
            newStack.setRegisters(currentStack.getRegisters())

        self.stacks.append(newStack)
        return True


    # Removes and returns the last element from the stacks lists.
    # @Return None if empty
    def pop(self):
        if len(self.stacks) < 1:
            return None

        popped =  self.stacks.pop()

        # Update the registers on the new currentStack (actually not needed)
        if self.getCurrentStack() is not None:
            self.getCurrentStack().setRegisters(popped.getRegisters())
        return popped

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

    def getVariables(self):
        return self.getCurrentStack().getVariables()
