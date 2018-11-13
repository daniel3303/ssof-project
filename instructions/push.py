class Push(Instruction):

    def __init__(self, address, value):
        Instruction.__init__(self, address)
        self.op = "push"
        self.value = value