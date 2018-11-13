class Je(Instruction):

    def __init__(self, address, targetAddress):
        Instruction.__init__(self, address)
        self.op = "je"
        self.targetAddress = targetAddress