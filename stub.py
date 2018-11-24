#!/usr/bin/python

# Description: Decryption AES tool in CBC mode
# Author: Alvaro Trigo

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
import sys
import argparse
import subprocess

##	Define arguments

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="File to decrypt")
parser.add_argument("-k", "--key", help="Key to use in the decryption")
args = parser.parse_args()

##	If execute the script without parameters, show help

if(len(sys.argv)==1):
	print("")
	subprocess.call([sys.argv[0], '-h'])
	print("")
	sys.exit()

##	Create the key with 32 bits lenght using SHA256

secret = SHA256.new(args.key).digest()

##	Configure block size and exit file

bs = 16
clean_file = args.file + '.clean'

##	Create decrypther
with open(args.file, 'rb') as cyphered:
	with open(clean_file, 'wb') as clean:
		iv = cyphered.read(AES.block_size)
		stub = AES.new(secret, AES.MODE_CBC, iv)
		while True:
			block = cyphered.read(bs)
			if len(block) == 0:
				break
			clean.write(stub.decrypt(block))