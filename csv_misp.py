#!/usr/bin/python

#####################################################################################################################################################
# Description: Script which fetchs information of MISP system in an specific period time in CSV format.                                                           #
# Requirements: A config file dubbed misp.cnf must be exist. This file could be storaged in the same path of the script (recommended) or other path.#
# Author: Alvaro Trigo                                                                                                                              #
#####################################################################################################################################################

import urllib2
import urllib
import ssl
import os
import sys
import datetime

# Global variables:
key = ""
misp_server_url = ""
time_schedule = ""
types = []
flag_header = 0

# Local functions:

def get_timestamp():
        timestamp = str(datetime.datetime.now())
        timestamp = timestamp[:19]
        timestamp = timestamp.replace("-","")
        timestamp = timestamp.replace(":","")
        timestamp = timestamp.replace(" ","")
        return timestamp

def get_config(path):
        global key, misp_server_url, time_schedule, types
        if (path == ""):
                path = os.getcwd()
                path = path + "/misp.cnf"
        try:
                file = open(path)
                line = file.readline().rstrip('\n')
        except:
                print "[-] Error opening the config file. Please, check the path."
                sys.exit(0)
        while line != '':
                if line.find("key") != -1:
                        equal_pos = line.find("=")
                        if line[equal_pos+1] == " ":
                                key = line[equal_pos+2:]
                        else:
                                key = line[equal_pos+1:]
                if line.find("misp_server_url") != -1:
                        equal_pos = line.find("=")
                        if line[equal_pos+1] == " ":
                                misp_server_url = line[equal_pos+2:]
                        else:
                                misp_server_url = line[equal_pos+1:]
             	if line.find("time_schedule") != -1:
                        equal_pos = line.find("=")
                        if line[equal_pos+1] == " ":
                                time_schedule = line[equal_pos+2:]
                        else:
                                time_schedule = line[equal_pos+1:]
                if line.find("types") != -1:
                        equal_pos = line.find("=")
                        if line[equal_pos+1] == " ":
                                var_types = line[equal_pos+2:]
                        else:
                                var_types = line[equal_pos+1:]
                        # in var_types you have the string representation of the list. Now, we have to convert it to list:
                        types = var_types.split()
                line = file.readline().rstrip('\n')
        file.close()

#####################################################################################################################################################

# Main function

#####################################################################################################################################################

print '___  ___ __  __  ____     ____  _  _'
print '||\\//|| || (( \ || \\    || \\ \\//'
print '|| \/ || ||  \\  ||_//    ||_//  )/'
print '||    || || \_)) ||    || ||    //'
print ''
print 'MISP gathering tool, v0.1 (CSV Format version). Alvaro Trigo.'
print ''

try:
        get_config("")
except:
        print "[-] Error opening the config file. Please, check the path."
        sys.exit(0)

print '[+] Fetching the results of ' + time_schedule
print ''

report_path = get_timestamp()
report_path = "report" + "_" + report_path + ".csv"

f = open(report_path, "a")

for tipo in types:
        url = misp_server_url + "/events/csv/download/false/false/false/false/" + tipo + "/false/false/false/" + time_schedule
        context = ssl._create_unverified_context()
        request = urllib2.Request(url, headers={"Authorization" : key, "Accept" : "application/csv", "Content-Type" : "application/csv"})
        values = urllib2.urlopen(request, context=context)
        for value in values:
                if value.find("uuid,event_id,category,type,value,comment,to_ids,date") != -1:
                        if flag_header == 0:
                                flag_header = 1
                                print value.rstrip('\n')
                                f.write(value.rstrip('\n') + '\n')
                else:
                        if value.find("Not Malicious") == -1:
                                print value.rstrip('\n')
                                f.write(value.rstrip('\n') + '\n')
        values.close()
f.close()
