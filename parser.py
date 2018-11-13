import sys
import json
from function import Function
from factories import *

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
        variables = self.code["main"]["variables"]
        instructions = self.code["main"]["instructions"]

        main = Function("main")
        for variable in variables:
            main.addVariable(self.variableFactory.constructFromJson(variable))

        for instruction in instructions:
            main.addInstruction(self.instructionFactory.constructFromJson(instruction))


inputFile = sys.argv[1]
parser = Parser(inputFile)
parser.parse()


