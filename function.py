class Function:
    
    def __init__(self, function_name):
        self.name = function_name
        self.instructions = []
        self.variables = []

    def addInstruction(self, instruction):
        self.instructions.append(instruction)

    def addVariable(self, variable):
        self.variables.append(variable)