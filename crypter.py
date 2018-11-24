#!/usr/bin/python

# Description: Encryption tool using AES in CBC mode
# Author: Alvaro Trigo

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
import sys
import argparse
import subprocess

##	Define arguments

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="File to encrypt")
parser.add_argument("-k", "--key", help="Key to use in the encryption")
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
cyphered = args.file + '.aes'

##	Create IV

iv = Random.new().read(AES.block_size)

##	Create cypher

cypher = AES.new(secret, AES.MODE_CBC, iv)
with open(args.file, 'rb') as clean:
	with open(cyphered, 'wb') as cifrado:
		cifrado.write(iv)
		while True:
			block = clean.read(bs)
			if len(block) == 0:
				break
			else:
				fill = bs - len(block) % bs
				block += ' '.encode(encoding='UTF-8') * fill
			cifrado.write(cypher.encrypt(block))