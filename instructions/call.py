class Call(Instruction):

    def __init__(self, address, fName, fAddress):
        Instruction.__init__(self, address)
        self.op = "call"
        self.fName = fName
        self.fAddress = fAddress