# Models the known stack
class Stack:
	def __init__(self):
		self.elements = {} # key is start addr

	def elementExists(key):
		return key in self.elements

	def addElement(stackElement):
		if(self.canAddElementToStack(stackElement)):
			self.elements[stackElement.startAddr, stackElement]

	def getElement(key):
		if key in self.elements:
			return self.elements[key]

	def delElement(key):
		if key in self.elements:
			del self.elements[key]

	def updateElement(key, stackElement):
		oldElement = self.getElement(key)
		if key in self.elements:
			self.delElement(key)

		if(self.canAddElementToStack(stackElement)):
			addElement(stackElement)
		else:
			self.addElement(oldElement);
			raise Exception('Element does not fit in stack')

	def isAddressIntervalFree(startAddr1, endAddr1):
		tempElement = StackElement(startAddr1, startADdr1-endAddr1, "")
		return self.canAddElementToStack(tempElement)

	def canAddElementToStack(stackElement):
		for el in self.elements:
			if self.elementsOverlap(el, stackElement): 
				return False
		return True

	def elementsOverlap(stackElement1, stackElement2):
		range1 = range(stackElement1.startAddr, stackElement1.endAddr)
		range2 = range(stackElement2.startAddr, stackElement2.endAddr)
		return len(range1.intersection(range2)) > 0 
	

class StackElement:
	# addresses in hex, size in bytes (int)
	def __init__(self, startAddr, size, content):
		self.startAddr = startAddr
		self.size = size
		self.content = content
		self.endAddr = startAddr+hex(size)
