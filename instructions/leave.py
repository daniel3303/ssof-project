class Leave(Instruction):

    def __init__(self, address):
        Instruction.__init__(self, address)
        self.op = "leave"