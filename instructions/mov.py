class Mov(Instruction):

    def __init__(self, address, dest, value):
        Instruction.__init__(self, address)
        self.op = "mov"
        self.dest = dest
        self.value = value