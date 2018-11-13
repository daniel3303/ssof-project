class Cmp(Instruction):

    def __init__(self, address, arg0, arg1):
        Instruction.__init__(self, address)
        self.op = "cmp"
        self.arg0 = arg0
        self.arg1 = arg1