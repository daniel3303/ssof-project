from variable import Variable
from instructions import *

class VariableFactory:
	# This constructs python objects representing variables from the JSON input file
	def constructFromJson(self, jsonObject):
		return Variable(jsonObject["name"], jsonObject["type"], jsonObject["bytes"], jsonObject["address"])

class InstructionFactory:   

	# This constructs python objects representing instructions from the JSON input file
	def constructFromJson(self, jsonObject):
		# for this program we can consider 32 bit registers as 64 bit ones
		if "args" in jsonObject and "dest" in jsonObject["args"]:
			if  jsonObject["args"]["dest"][0]=="e":
				jsonObject["args"]["dest"] = "r" + jsonObject["args"]["dest"][1:]

		instruction = None		
		if(jsonObject["op"] == "add"):
			instruction = Add(jsonObject["address"], jsonObject["args"]["dest"], jsonObject["args"]["value"], jsonObject["pos"])
		if(jsonObject["op"] == "lea"):
			instruction =Lea(jsonObject["address"], jsonObject["args"]["dest"], jsonObject["args"]["value"], jsonObject["pos"])
		if(jsonObject["op"] == "mov"):
			instruction =Mov(jsonObject["address"], jsonObject["args"]["dest"], jsonObject["args"]["value"], jsonObject["pos"])
		if(jsonObject["op"] == "sub"):
			instruction =Sub(jsonObject["address"], jsonObject["args"]["dest"], jsonObject["args"]["value"], jsonObject["pos"])
		if(jsonObject["op"] == "call"):
			instruction =Call(jsonObject["address"], jsonObject["args"]["fnname"], jsonObject["args"]["address"], jsonObject["pos"])
		if(jsonObject["op"] == "cmp"):
			instruction =Cmp(jsonObject["address"], jsonObject["args"]["arg0"], jsonObject["args"]["arg1"], jsonObject["pos"])
		if(jsonObject["op"] == "test"):
			instruction =Test(jsonObject["address"], jsonObject["args"]["arg0"], jsonObject["args"]["arg1"], jsonObject["pos"])
		if(jsonObject["op"] == "je"):
			instruction =Je(jsonObject["address"], jsonObject["args"]["address"], jsonObject["pos"])
		if(jsonObject["op"] == "jmp"):
			instruction =Jmp(jsonObject["address"], jsonObject["args"]["address"], jsonObject["pos"])
		if(jsonObject["op"] == "jne"):
			instruction =Jne(jsonObject["address"], jsonObject["args"]["address"], jsonObject["pos"])
		if(jsonObject["op"] == "leave"):
			instruction =Leave(jsonObject["address"], jsonObject["pos"])
		if(jsonObject["op"] == "nop"):
			instruction =Nop(jsonObject["address"], jsonObject["pos"])
		if(jsonObject["op"] == "ret"):
			instruction =Ret(jsonObject["address"], jsonObject["pos"])
		if(jsonObject["op"] == "push"):
			instruction =Push(jsonObject["address"], jsonObject["args"]["value"], jsonObject["pos"])

 		# format string in args.obs
		if "args" in jsonObject and "obs" in jsonObject["args"]:
			instruction.obs = jsonObject["args"]["obs"]

		return instruction




