class Sub(Instruction):

    def __init__(self, address, dest, value):
        Instruction.__init__(self, address)
        self.op = "sub"
        self.dest = dest
        self.value = value 