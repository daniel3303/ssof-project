class Instruction:

	def __init__(self, address, pos):
		self.address = address
		self.op = ""
		self.obs = None # format string purposes
		self.pos = pos
		self.executed = False
		self.skip = False # for jumps

	#def execute(self, context): FIXME is this being used?
		#executer(self, context)

	def accept(self, visitor):
		visitor.visit(self)

class Add(Instruction):

	def __init__(self, address, dest, value, pos):
		Instruction.__init__(self, address, pos)
		self.op = "add"
		self.dest = dest
		self.value = value

class Call(Instruction):

	def __init__(self, address, fName, fAddress,pos):
		Instruction.__init__(self, address, pos)
		self.op = "call"
		self.fName = fName
		self.fAddress = fAddress

class Cmp(Instruction):

	def __init__(self, address, arg0, arg1,pos):
		Instruction.__init__(self, address, pos)
		self.op = "cmp"
		self.arg0 = arg0
		self.arg1 = arg1

class Je(Instruction):

	def __init__(self, address, targetAddress,pos):
		Instruction.__init__(self, address, pos)
		self.op = "je"
		self.targetAddress = targetAddress

class Jmp(Instruction):

	def __init__(self, address, targetAddress,pos):
		Instruction.__init__(self, address, pos)
		self.op = "jmp"
		self.targetAddress = targetAddress

class Jne(Instruction):

	def __init__(self, address, targetAddress,pos):
		Instruction.__init__(self, address, pos)
		self.op = "jne"
		self.targetAddress = targetAddress

class Lea(Instruction):

	def __init__(self, address, dest, value,pos):
		Instruction.__init__(self, address, pos)
		self.op = "lea"
		self.dest = dest
		self.value = value

class Leave(Instruction):

	def __init__(self, address,pos):
		Instruction.__init__(self, address, pos)
		self.op = "leave"

class Mov(Instruction):

	def __init__(self, address, dest, value,pos):
		Instruction.__init__(self, address, pos)
		self.op = "mov"
		self.dest = dest
		self.value = value

class Nop(Instruction):

	def __init__(self, address,pos):
		Instruction.__init__(self, address, pos)
		self.op = "nop"

class Push(Instruction):

	def __init__(self, address, value ,pos):
		Instruction.__init__(self, address, pos)
		self.op = "push"
		self.value = value

class Ret(Instruction):

	def __init__(self, address,pos):
		Instruction.__init__(self, address, pos)
		self.op = "ret"

class Sub(Instruction):

	def __init__(self, address, dest, value,pos):
		Instruction.__init__(self, address, pos)
		self.op = "sub"
		self.dest = dest
		self.value = value

class Test(Instruction):

	def __init__(self, address, arg0, arg1,pos):
		Instruction.__init__(self, address, pos)
		self.op = "test"
		self.arg0 = arg0
		self.arg1 = arg1