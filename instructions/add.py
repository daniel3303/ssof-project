class Add(Instruction):

    def __init__(self, address, dest, value):
        Instruction.__init__(self, address)
        self.op = "add"
        self.dest = dest
        self.value = value