#Visitor pattern class
from vulnerabilities import *
from instructions import *

class Executer:

    # "Overloading" ʕ ͡° ʖ̯ ͡°ʔ
    def visit(self, instruction, context):
        if type(instruction) is Add:
            self.visitAdd(instruction, context)
        if type(instruction) is Call:
            self.visitCall(instruction, context)
        if type(instruction) is Cmp:
            self.visitCmp(instruction, context)
        if type(instruction) is Je:
            self.visitJe(instruction, context)
        if type(instruction) is Jmp:
            self.visitJmp(instruction, context)
        if type(instruction) is Jne:
            self.visitJne(instruction, context)
        if type(instruction) is Lea:
            self.visitLea(instruction, context)
        if type(instruction) is Leave:
            self.visitLeave(instruction, context)
        if type(instruction) is Mov:
            self.visitMov(instruction, context)
        if type(instruction) is Nop:
            self.visitNop(instruction, context)
        if type(instruction) is Push:
            self.visitPush(instruction, context)
        if type(instruction) is Ret:
            self.visitRet(instruction, context)
        if type(instruction) is Sub:
            self.visitSub(instruction, context)
        if type(instruction) is Test:
            self.visitTest(instruction, context)

    # :::::::: Visit methods ::::::::::

    def visitAdd(self, instruction, context):
        print(instruction.op)

    def visitCall(self, instruction, context):
        print(instruction.op)

    def visitCmp(self, instruction, context):
        print(instruction.op)
        
    def visitJe(self, instruction, context):
        print(instruction.op)
        
    def visitJmp(self, instruction, context):
        print(instruction.op)

    def visitJne(self, instruction, context):
        print(instruction.op)

    def visitLea(self, instruction, context):
        print(instruction.op)

    def visitLeave(self, instruction, context):
        print(instruction.op)

    def visitMov(self, instruction, context):
        print(instruction.op)

    def visitNop(self, instruction, context):
        print(instruction.op)

    def visitPush(self, instruction, context):
        print(instruction.op)

    def visitRet(self, instruction, context):
        print(instruction.op)

    def visitSub(self, instruction, context):
        print(instruction.op)

    def visitTest(self, instruction, context):
        print(instruction.op)


    