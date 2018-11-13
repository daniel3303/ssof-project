class Nop(Instruction):

    def __init__(self, address):
        Instruction.__init__(self, address)
        self.op = "nop"