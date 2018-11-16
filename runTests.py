import sys
import os
import errno
import glob
import json
import subprocess
import parser

path = 'tests/*.json'
inFiles = [name for name in glob.glob(path) if 'output' not in os.path.basename(name)]
out = ""
testPassCtr = 0

for name in inFiles:
	out += "#### FILE: " + name + "\n"
	try:
		parser = Parser(name)
		context = parser.parse()
		context.execute()

		result = []
		for vuln in context.vulnerabilities:
			result.append(vuln.toJSON())

	except:
		result = ""
	#out += result
	out += "-------------------------------------------------\n\n"
	try:
		expectedOutFile = name[:-5] + ".output.json"
		outFile = open(expectedOutFile, 'r')
		outJSON = outFile.read()
		outJSON = json.loads(outJSON)
	except:
		outJSON = {}
	if(result == outJSON):
		print("TEST PASS: " + name)
		testPassCtr+=1
	else:
		print("TEST FAIL: " + name)




file = open('TEST_OUTPUT.txt', 'w')
file.write(out)
print(str(testPassCtr) + "/" + str(len(inFiles)) + " tests passed")
