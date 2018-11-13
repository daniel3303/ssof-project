class Jne(Instruction):

    def __init__(self, address, targetAddress):
        Instruction.__init__(self, address)
        self.op = "jne"
        self.targetAddress = targetAddress