# Models the known stack
class Stack:
	def __init__(self):
		# key is start addr relative to RBP with minus, ex: -0x4 is RBP-0x4
		# for RBP+0x4 we have 0x4
		self.elements = {} 

	def elementExists(self, key):
		return key in self.elements

	def addElement(self, stackElement):
		if(self.canAddElementToStack(stackElement)):
			self.elements[stackElement.startAddr] = stackElement;

	def getElement(self, key):
		if key in self.elements:
			return self.elements[key]

	def delElement(self, key):
		if key in self.elements:
			del self.elements[key]

	def updateElement(self, stackElement):
		key = stackElement.startAddr
		oldElement = self.getElement(key)
		if key in self.elements:
			self.delElement(key)

		if(self.canAddElementToStack(stackElement)):
			addElement(stackElement)
		else:
			self.addElement(oldElement);
			raise Exception('Element does not fit in stack')

	def isAddressIntervalFree(self, startAddr1, endAddr1):
		tempElement = StackElement(startAddr1, startADdr1-endAddr1, "")
		return self.canAddElementToStack(tempElement)

	def canAddElementToStack(self, stackElement):
		for key in self.elements:
			if self.elementsOverlap(self.elements[key], stackElement): 
				return False
		return True

	def elementsOverlap(self, stackElement1, stackElement2):
		print("type startaddr1: {}".format(type(stackElement1.startAddr)))
		print("type endaddr1: {}  endaddr2: {}".format(type(stackElement1.endAddr), type(stackElement2.endAddr)))

		range1 = range(stackElement1.startAddr, stackElement1.endAddr)
		range2 = range(stackElement2.startAddr, stackElement2.endAddr)
		
		return len(set(range1) & set(range2)) > 0 
	

class StackElement:
	# addresses in hex, size in bytes (int)
	def __init__(self, startAddr, size, content):
		self.startAddr = startAddr
		self.size = size
		self.content = content
		self.endAddr = startAddr + size
