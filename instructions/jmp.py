class Jmp(Instruction):

    def __init__(self, address, targetAddress):
        Instruction.__init__(self, address)
        self.op = "jmp"
        self.targetAddress = targetAddress