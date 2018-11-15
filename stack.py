from function import *

class Stack:
    def __init__(self, function):
        self.function = function
        self.values = {} # TODO init values from variables

        #Checks if the function argument is from type Function
        if not issubclass(function.__class__, Function):
            raise Error("Invalid argument. @param function must be an instace of Function.")

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


    def getFunction(self):
        return self.function

    def getRegisters(self):
        return self.registers

    def isRegister(self, name):
        return name in self.registers

    def setValue(self, location, value):
        #TODO check invalid writes

        if self.isRegister(location):
			self.context.registers[location] = value

        elif self.isStackAddress(location):
            self.values[self.getStackValueAddress(location)] = value



    def isStackAddress(self, location):
    	return isinstance(location, basestring) and "[rbp" in memPos

    def getStackValueAddress(self, memPos):
    	return memPos[memPos.find('[rbp')+5:memPos.find(']')]



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
