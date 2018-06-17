#!/usr/bin/python

###############################################################################################################

##	Security test python script.
##	Execute web app and infraestructure scanners in DevOps pipeline
##	by Alvaro Trigo

###############################################################################################################

import subprocess
import sys
import argparse
import datetime

##	Define arguments

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dast", help="Execute web dynamic security test on selected target", action="store_true")
parser.add_argument("-w", "--wordpress", help="Execute Wordpress test", action="store_true")
parser.add_argument("-i", "--infra", help="Execute infraestructure test", action="store_true")
parser.add_argument("-t", "--target", help="Target to check. It could be an IP or an URL")
args = parser.parse_args()

##	Obtain timestamp variable

timestamp = str(datetime.datetime.now())
timestamp = timestamp[:19]
timestamp = timestamp.replace("-","")
timestamp = timestamp.replace(":","")
timestamp = timestamp.replace(" ","")

##	If execute the script without parameters, show help

if(len(sys.argv)==1):
        subprocess.call([sys.argv[0], '-h'])

##	Executing tests

if args.infra:
	if args.target is not None:
		subprocess.call(['nikto','-h', args.target])
        	subprocess.call(['nmap','-sV','-A','-O','-p1-65535', args.target])
		subprocess.call(['sslscan', args.target + ':443'])
	else:
	        print sys.argv[0][2:] + ": error: argument -d/--dast: a valid IP or URL must be selected using -t/--target option"
if args.wordpress:
	if args.target is not None:
       		print "IP selected: " + args.target
        	subprocess.call(['wpscan', '--update'])
        	subprocess.call(['wpscan', '--url', args.target])
	else:
                print sys.argv[0][2:] + ": error: argument -d/--dast: a valid IP or URL must be selected using -t/--target option"
if args.dast:
	if args.target is not None:
       		subprocess.call(['skipfish','-o' + str(timestamp), args.target])
	else:
                print sys.argv[0][2:] + ": error: argument -d/--dast: a valid IP or URL must be selected using -t/--target option"
