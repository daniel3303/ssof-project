import sys
import json
from function import Function
from factories import *
from context import Context

class Parser:
    def __init__(self, fileName):
        self.fileName = fileName
        self.loadCode(fileName)
        self.instructionFactory = InstructionFactory()
        self.variableFactory = VariableFactory()

    def loadCode(self, fileName):
        with open(fileName) as inputFile:
            self.code = json.load(inputFile)
            
    
    def parse(self):
        context = Context()
        for fnName, fnData in self.code.items():
            function = Function(fnName)
            variables = self.code[fnName]["variables"]
            instructions = self.code[fnName]["instructions"]
            
            for variable in variables:
                function.addVariable(self.variableFactory.constructFromJson(variable))

            for instruction in instructions:
                function.addInstruction(self.instructionFactory.constructFromJson(instruction))
            
            context.addFunction(function)
        return context

''' TESTING '''
inputFile = sys.argv[1]
parser = Parser(inputFile)
context = parser.parse()
context.execute()


