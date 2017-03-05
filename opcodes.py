#!/usr/bin/python

"""
1. Compile the binary with gcc: gcc binary.c -o binary
2. Execute Objdump tool and redirect the result to a file: objdump -M intel -d binary > file.txt
3. Execute parser: ./opcodes.py _init file.txt
"""

import sys

print ""
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print "+++                                                        +++"
print "+++    Objdump file to opcodes parser  (by Alvaro Trigo)   +++"
print "+++                                                        +++"
print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
print ""

if(len(sys.argv)<3):
	print "Usage: " + sys.argv[0] + " <function name> <file with opcodes>"
	print "<funtion name>: _init"
	print "<file with opcodes>: The file with opcodes can be extracted from objdump tool."
	print ""
	sys.exit(0)

f = open(sys.argv[2], "r")
function = "<" + sys.argv[1] + ">:"
print "Getting opcodes from " + function
print ""

# Initializing variables:

flag = 0  	# Used to detect the function in the file
contador = 0 	# Used to count the length of the shellcode
shellcode="" 	# Variable in which will be placed the opcodes of the shellcode

for linea in f:
	if(flag == 1):
		if(linea.find(":") != -1):
			linea = linea[linea.find(":")+2:]	# Remove stack direction of the line
			linea = linea[0:22]			# The first 23 (22+1) characters are the opcodes
			print linea
			flag2=0
			i=0
			while(flag2 == 0):
				if(linea[i+3] == " "):
					flag2=1
				shellcode = shellcode + "\\x" + linea[i] + linea[i+1]
				contador=contador+1
				i=i+3 
		else:
			flag = 0
	if(linea.find(function) != -1):
		flag=1
print ""
print "Shellcode length: " + str(contador) + " bytes"
print ""
print "shellcode =" + "\"" + shellcode + "\""
print ""
