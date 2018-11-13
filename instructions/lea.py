class Lea(Instruction):

    def __init__(self, address, dest, value):
        Instruction.__init__(self, address)
        self.op = "lea"
        self.dest = dest
        self.value = value