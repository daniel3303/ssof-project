# This script is optional and was developed to aid the testing and debugging process of the project
# it runs the program on each test input file ending in .json and not in .output.json
# from a tests folder

import sys
import os
import errno
import glob
import json
import subprocess
from main import Parser


path = 'tests/*.json'
inFiles = [name for name in glob.glob(path) if 'output' not in os.path.basename(name)]
out = ""
testPassCtr = 0

# Printing with colors for test result visibility 
#https://stackoverflow.com/questions/287871/print-in-terminal-with-colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Compare two json objects with vunarabilities
def same_vunerabilities(a, b):
	if len(a) != len(b):
		print("Found vunerabilities: "+str(len(a))+"\nExpected: "+str(len(b)))
		return False

	for vul in a:
		found = False
		for vul2 in b:
			if sorted(vul.items()) == sorted(vul2.items()):
				found = True
		if found == False:
			return False
		else:
			found = False
	return True

print("######################################################")
print("\t\t EXECUTING TESTS")
print("######################################################")
for name in inFiles:
	out += "#### FILE: " + name + "\n"
	try:
		parser = Parser(name)
		context = parser.parse()
		context.execute()

		result = []
		for vuln in context.vulnerabilities:
			result.append(vuln.toJSON())

	except Exception as exp:
		print(exp)
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

	print("#----------------------------------------------------#")
	if same_vunerabilities(result, outJSON):
		print("TEST PASS: " + name)
		testPassCtr+=1
	else:
		print(bcolors.FAIL + "TEST FAIL: " + name + bcolors.ENDC)
	print("#----------------------------------------------------#\n\n")



file = open('TEST_OUTPUT.txt', 'w')
file.write(out)
print(str(testPassCtr) + "/" + str(len(inFiles)) + " tests passed")
