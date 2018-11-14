from executer import Executer

class Function:
    
    def __init__(self, function_name):
        self.name = function_name
        self.instructions = []
        self.variables = []

    def addInstruction(self, instruction):
        self.instructions.append(instruction)

    def addVariable(self, variable):
        self.variables.append(variable)

    def execute(self, context):
        #add vars
        executer = Executer()
        for instruction in self.instructions:
            instruction.accept(executer, context)