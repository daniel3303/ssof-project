import json

class Vulnerability:
	def __init__(self, function, address, fnname, overflowVar):
		self.function = function
		self.address = address
		self.fnname = fnname
		self.overflowVar = overflowVar

	def toJSON(self):
		data = {}
		data['vuln_function'] = self.function
		data['address'] = self.address
		data['fnname'] = self.fnname
		data['overflow_var'] = self.overflowVar
		return data

class VarOverflow(Vulnerability):
	def __init__(self, function, address, fnname, overflowingVar, overflownVar):
		Vulnerability.__init__(self,  function, address, fnname, overflowingVar)
		self.overflownVar = overflownVar

	def toJSON(self):
		jsonData = Vulnerability.toJSON(self)
		jsonData['vulnerability'] = 'VAROVERFLOW'
		jsonData['overflown_var'] = self.overflownVar
		return jsonData

class RBPOverflow(Vulnerability):
	def __init__(self, function, address, fnname, overflowingVar):
		Vulnerability.__init__(self,  function, address, fnname, overflowingVar)

	def toJSON(self):
		jsonData = Vulnerability.toJSON(self)
		jsonData['vulnerability'] = 'RBPOVERFLOW'
		return jsonData

class RetOverflow(Vulnerability):
	def __init__(self, function, address, fnname, overflowingVar):
		Vulnerability.__init__(self,  function, address, fnname, overflowingVar)

	def toJSON(self):
		jsonData = Vulnerability.toJSON(self)
		jsonData['vulnerability'] = 'RETOVERFLOW'
		return jsonData

# Advanced
class InvalidAccess(Vulnerability):
	def __init__(self, function, address, fnname, overflowVar, overflownAddress):
		Vulnerability.__init__(self,  function, address, fnname, overflowVar)
		self.overflownAddress = overflownAddress

	def toJSON(self):
		jsonData = Vulnerability.toJSON(self)
		jsonData['vulnerability'] = 'INVALIDACCS'
		jsonData['overflown_address'] = self.overflownAddress
		return jsonData

class StackCorruption(Vulnerability):
	def __init__(self, function, address, fnname, overflowingVar, overflownAddress):
		Vulnerability.__init__(self,  function, address, fnname, overflowingVar)
		self.overflownAddress = overflownAddress

	def toJSON(self):
		jsonData = Vulnerability.toJSON(self)
		jsonData['vulnerability'] = 'SCORRUPTION'
		jsonData['overflown_address'] = self.overflownAddress
		return jsonData

class DirectInvalidAccess(Vulnerability):
	def __init__(self, function, address, overflownAddress):
		Vulnerability.__init__(self,  function, address, "", "")
		self.overflownAddress = overflownAddress

	def toJSON(self):
		jsonData = Vulnerability.toJSON(self)
		jsonData['vulnerability'] = 'INVALIDACCS'
		jsonData['overflown_address'] = self.overflownAddress
		del jsonData['fnname']
		del jsonData['overflow_var']
		return jsonData

class DirectStackCorruption(Vulnerability):
	def __init__(self, function, address, overflownAddress):
		Vulnerability.__init__(self,  function, address, "", "")
		self.overflownAddress = overflownAddress

	def toJSON(self):
		jsonData = Vulnerability.toJSON(self)
		jsonData['vulnerability'] = 'SCORRUPTION'
		jsonData['overflown_address'] = self.overflownAddress
		del jsonData['fnname']
		del jsonData['overflow_var']
		return jsonData

''' TESTING
vo = VarOverflow('main', '4005ab', 'fgets', 'buf', 'control')
rbpo = RBPOverflow('main', '4005ab', 'fgets', 'buf')
reto = RetOverflow('main', '4005ab', 'fgets', 'buf')
invacc = InvalidAccess('main', '4005ab', 'fgets', 'buf', 'rbp-0x10')
scorr = StackCorruption('main', '4005ab', 'fgets', 'buf', 'rbp-0x10')

out = []
out.append(vo.toJSON())
out.append(rbpo.toJSON())
out.append(reto.toJSON())
out.append(invacc.toJSON())
out.append(scorr.toJSON())
print(json.dumps(out, indent=4, separators=(',', ': ')))
'''