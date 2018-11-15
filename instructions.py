class Instruction:

	def __init__(self, address):
		self.address = address
		self.op = ""

	#def execute(self, context): FIXME is this being used?
		#executer(self, context)

	def accept(self, visitor, context):
		visitor.visit(self, context)

class Add(Instruction):

	def __init__(self, address, dest, value):
		Instruction.__init__(self, address)
		self.op = "add"
		self.dest = dest
		self.value = value

class Call(Instruction):

	def __init__(self, address, fName, fAddress):
		Instruction.__init__(self, address)
		self.op = "call"
		self.fName = fName
		self.fAddress = fAddress

class Cmp(Instruction):

	def __init__(self, address, arg0, arg1):
		Instruction.__init__(self, address)
		self.op = "cmp"
		self.arg0 = arg0
		self.arg1 = arg1

class Je(Instruction):

	def __init__(self, address, targetAddress):
		Instruction.__init__(self, address)
		self.op = "je"
		self.targetAddress = targetAddress

class Jmp(Instruction):

	def __init__(self, address, targetAddress):
		Instruction.__init__(self, address)
		self.op = "jmp"
		self.targetAddress = targetAddress

class Jne(Instruction):

	def __init__(self, address, targetAddress):
		Instruction.__init__(self, address)
		self.op = "jne"
		self.targetAddress = targetAddress

class Lea(Instruction):

	def __init__(self, address, dest, value):
		Instruction.__init__(self, address)
		self.op = "lea"
		self.dest = dest
		self.value = value

class Leave(Instruction):

	def __init__(self, address):
		Instruction.__init__(self, address)
		self.op = "leave"

class Mov(Instruction):

	def __init__(self, address, dest, value):
		Instruction.__init__(self, address)
		self.op = "mov"
		self.dest = dest
		self.value = value

class Nop(Instruction):

	def __init__(self, address):
		Instruction.__init__(self, address)
		self.op = "nop"

class Push(Instruction):

	def __init__(self, address, value):
		Instruction.__init__(self, address)
		self.op = "push"
		self.value = value

class Ret(Instruction):

	def __init__(self, address):
		Instruction.__init__(self, address)
		self.op = "ret"

class Sub(Instruction):

	def __init__(self, address, dest, value):
		Instruction.__init__(self, address)
		self.op = "sub"
		self.dest = dest
		self.value = value

class Test(Instruction):

	def __init__(self, address, arg0, arg1):
		Instruction.__init__(self, address)
		self.op = "test"
		self.arg0 = arg0
		self.arg1 = arg1
