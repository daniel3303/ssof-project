from variable import Variable
from instructions import *

class VariableFactory:
    
    def constructFromJson(self, jsonObject):
        return Variable(jsonObject["name"], jsonObject["type"], jsonObject["bytes"], jsonObject["address"])

class InstructionFactory:   

    def constructFromJson(self, jsonObject):
        if(jsonObject["op"] == "add"):
            return Add(jsonObject["address"], jsonObject["args"]["dest"], jsonObject["args"]["value"])
        if(jsonObject["op"] == "lea"):
            return Lea(jsonObject["address"], jsonObject["args"]["dest"], jsonObject["args"]["value"])
        if(jsonObject["op"] == "mov"):
            return Mov(jsonObject["address"], jsonObject["args"]["dest"], jsonObject["args"]["value"])
        if(jsonObject["op"] == "sub"):
            return Sub(jsonObject["address"], jsonObject["args"]["dest"], jsonObject["args"]["value"])
        
        if(jsonObject["op"] == "call"):
            return Call(jsonObject["address"], jsonObject["args"]["fnname"], jsonObject["args"]["address"])
        
        if(jsonObject["op"] == "cmp"):
            return Cmp(jsonObject["address"], jsonObject["args"]["arg0"], jsonObject["args"]["arg1"])
        if(jsonObject["op"] == "test"):
            return Test(jsonObject["address"], jsonObject["args"]["arg0"], jsonObject["args"]["arg1"])
        
        if(jsonObject["op"] == "je"):
            return Je(jsonObject["address"], jsonObject["args"]["address"])
        if(jsonObject["op"] == "jmp"):
            return Jmp(jsonObject["address"], jsonObject["args"]["address"])
        if(jsonObject["op"] == "jne"):
            return Jne(jsonObject["address"], jsonObject["args"]["address"])
        
        if(jsonObject["op"] == "leave"):
            return Leave(jsonObject["address"])
        if(jsonObject["op"] == "nop"):
            return Nop(jsonObject["address"])
        if(jsonObject["op"] == "ret"):
            return Ret(jsonObject["address"])
        
        if(jsonObject["op"] == "push"):
            return Push(jsonObject["address"], jsonObject["args"]["value"])

