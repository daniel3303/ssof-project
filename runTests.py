import sys
import os
import errno
import glob

path = 'tests/*.json'
inFiles = [name for name in glob.glob(path) if 'output' not in os.path.basename(name)]
out = ""
testPassCtr = 0;

for name in inFiles:
	out += "#### FILE: " + name + "\n"
	result = os.popen('python parser.py ' + name).read()
	out += result
	out += "-------------------------------------------------\n\n"

	expectedOutFile = name[:-5] + ".output.json"
	outFile = open(expectedOutFile, 'r')

	if(result == outFile.read()):
		print("TEST PASS: " + name)
		testPassCtr+=1
	else:
		print("TEST FAIL: " + name)


file = open('TEST_OUTPUT.txt', 'w')
file.write(out)

print(testPassCtr + "/" + len(inFiles) + " tests passed")

