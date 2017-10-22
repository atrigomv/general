#!/bin/bash

echo ""
echo -e "\e[0;34m[+]  finger.sh v0.2 by Alvaro Trigo \e[0m"
echo -e "\e[0;34m[+]  Starting fingerprint at" `date`  "\e[0m"
echo -e "\e[0;34m[+]  The target host has the follow IP:" $1 "\e[0m"

# Creating flag dirb

dirb="0"
dirb443="0"

# Creating the results folder:

mkdir $1 > /fichero 2>&1

# Checking if the host is up

touch $1/$1_ping.txt
ping -c 2 $1 > $1/$1_ping.txt
variable=`grep "bytes from" $1/$1_ping.txt`
if [ -z "$variable" ]
	then
	echo -e "\e[1;31m[+]  CAUTION: The host seems to be down or do not response to PING request!\e[0m"
else
	echo -e "\e[0;34m[+]  The host is up \e[0m"
fi
rm $1/$1_ping.txt

# Checking exisistance of DNS server:

echo -e "\e[0;34m[+]  DNS server detection...\e[0m"

touch $1/$1_dnsserver.txt
nmap -p 53 $1 -oG $1/$1_dnsserver.txt > /fichero 2>&1
variable=`grep "Status" $1/$1_dnsserver.txt | cut -d "(" -f 2 | cut -d ")" -f 1`
if [ -n "$variable" ]
	then
	echo -e "\e[0;34m[+]  The name of the remote machine is:" $variable " \e[0m"
fi

variable=`grep "Ports" $1/$1_dnsserver.txt | grep "open"`
if [ -z "$variable" ]
	then
	#NO DNS
	echo -e "\e[1;31m[+]  No DNS server detected\e[0m"
else
	#DNS
	echo -e "\e[1;32m[+]  DNS server detected!\e[0m"
fi
rm $1/$1_dnsserver.txt

# Detection of RDP:

echo -e "\e[0;34m[+]  RDP detection...\e[0m"

touch $1/$1_rdp.txt
nmap -p 3389 $1 -oG $1/$1_rdp.txt > /fichero 2>&1
variable=`grep "Ports:" $1/$1_rdp.txt | grep "open"`
if [ -z "$variable" ]
	then
	#NO RDP
	echo -e "\e[1;31m[+]  No RDP remote port detected\e[0m"
else
        #RDP
        echo -e "\e[1;32m[+]  RDP remote port detected!\e[0m"
	echo -e "\e[0;34m[+]  Checking if the machine is vulnerable to MS12-020 RDP vulnerability...\e[0m"
	nmap --script rdp-vuln-ms12-020.nse -p3389 --host-timeout 2m $1 -oN $1/$1_MS12_020_RDP.txt > /fichero 2>&1
	variable=`grep "Host script results" $1/$1_MS12_020_RDP.txt`
	if [ -z "$variable" ]
		then
		echo -e "\e[0;34m[+]  Not seems to be vulnerable\e[0m"
	else
		echo -e "\e[1;32m[+]  It could be vulnerable! A manual check is required (file in" $1/$1_MS12_020_RDP.txt")" "\e[0m"
	fi
fi
rm $1/$1_rdp.txt

# Detection of FTP:

echo -e "\e[0;34m[+]  FTP server detection...\e[0m"

touch $1/$1_ftp.txt
nmap -sV -P0 -p21 $1 -oG $1/$1_ftp.txt > /fichero 2>&1
variable=`grep "Ports:" $1/$1_ftp.txt | cut -d ":" -f 3 | cut -d " " -f 2 | cut -d "/" -f 1,2`
if [ $variable = "21/open" ]
	then
	variable=`grep "Ports:" $1/$1_ftp.txt | cut -d ":" -f 3 | cut -d " " -f 2 | cut -d "/" -f 7`
	echo -e "\e[1;32m[+]  "$variable "server detected!" "\e[0m"
	echo -e "\e[0;34m[+]  Brute forcing FTP service...\e[0m"
	touch $1/$1_ftp_brute.txt
	nmap -P0 --host-timeout 4m --script ftp-brute.nse -p21 $1 -oN $1/$1_ftp_brute.txt > /fichero 2>&1
	variable=`grep "Valid credentials" $1/$1_ftp_brute.txt`
	if [ -z "$variable" ]
		then
		echo -e "\e[0;34m[+]  No valid accounts found\e[0m"
	else
		echo -e "\e[1;32m[+]  Possible valid account found:" $variable "\e[0m"
	fi
else
	echo -e "\e[1;31m[+]  No FTP server detected\e[0m"
fi
rm $1/$1_ftp.txt

# Detection of SMB:

echo -e "\e[0;34m[+]  SMB service detection...\e[0m"

touch $1/$1_smb.txt
nmap -p 139,445 -oG $1/$1_smb.txt $1 > /fichero 2>&1
variable=`grep "Ports:" $1/$1_smb.txt | cut -d ":" -f 3 | cut -d "," -f 2 | cut -d " " -f 2 | cut -d "/" -f 1,2`
if [ $variable = "445/open" ]
	then
	variable=`grep "Ports:" $1/$1_smb.txt | cut -d ":" -f 3 | cut -d "," -f 1 | cut -d " " -f 2 | cut -d "/" -f 1,2`
	if [ $variable = "139/open" ]
		then
		echo -e "\e[1;32m[+]  SMB NetBIOS service detected!\e[0m"
	else
		echo -e "\e[1;32m[+]  SMB service detected!\e[0m"
	fi
	echo -e "\e[0;34m[+]  Detecting if SMBv2 is enabled in the target machine\e[0m"
	touch $1/$1_smb2.txt
	nmap --script=smbv2-enabled.nse $1 > $1/$1_smb2.txt
	variable=`grep "Server supports SMBv2 protocol" $1/$1_smb2.txt`
	if [ -n "$variable" ]
		then
		echo -e "\e[1;32m[+]  Target host supports SMBv2 protocol!\e[0m"
	else
		echo -e "\e[0:34m[+]  Target host does not support SMBv2 protocol\e[0m"
	fi

	echo -e "\e[0;34m[+]  Trying null session enumeration\e[0m"
	touch $1/$1_smb_nullsession.txt
	enum4linux -a $1 > $1/$1_smb_nullsession.txt
	variable=`grep "Aborting remainder of tests." $1/$1_smb_nullsession.txt`
	if [ -z "$variable" ]
		then
		echo -e "\e[1;32m[+]  Null session enumeration done!\e[0m"
	else
		echo -e "\e[0;34m[+]  The enumeration was not possible\e[0m"
	fi
else
	echo -e "\e[1;31m[+]  No SMB service detected\e[0m"
fi 
rm $1/$1_smb.txt

# Detection of SNMP:

echo -e "\e[0;34m[+]  SNMP detection...\e[0m"
touch $1/$1_community.txt
touch $1/$1_snmp.txt
echo public > $1/$1_community.txt
echo private >> $1/$1_community.txt
echo manager >> $1/$1_community.txt
onesixtyone $1 -c $1/$1_community.txt > $1/$1_snmp.txt 
rm $1/$1_community.txt
echo -e "\e[0;34m[+]  SNMP detection done. Check the results in the next file:" $1/$1_snmp.txt "\e[0m"

# Detection of web apps:

echo -e "\e[0;34m[+]  Web application detection...\e[0m"

touch $1/$1_webapp.txt
nmap -p 80,443,8000,8080 $1 -oG $1/$1_webapp.txt > /fichero 2>&1
variable=`grep Ports $1/$1_webapp.txt | cut -d " " -f 4,5 | grep "open"`
if [ -z "$variable" ]
	then
	#NO web app"
	echo -e "\e[1;31m[+]  No web application detected\e[0m"
else
	#web app"
	echo -e "\e[1;32m[+]  Web application detected!\e[0m"
	variable=`grep "filtered" $1/$1_webapp.txt`
	if [ -n "$variable" ]
	then
	echo -e "\e[0;34m[+]  There are some web applications behind the firewall (filtered). Manual check is required\e[0m"
	fi
	variable=`grep "Ports:" $1/$1_webapp.txt | cut -d ":" -f 3 | cut -d "/" -f 1,2`
	if [ $variable = "80/open" ]
		then
		#80 open"
		dirb="1"
		echo -e "\e[1;35m[+]  80/tcp port detected as open\e[0m"
		echo -e "\e[0;34m[+]  Executing Nikto scanner on 80/tcp port...\e[0m"
		touch $1/$1_nikto80.txt
		nikto -h $1:80 > $1/$1_nikto80.txt
		echo -e "\e[0;34m[+]  Nikto analysis done\e[0m"
		echo -e "\e[0;34m[+]  Executing Skipfish scanner on 80/tcp port...\e[0m"
                cd $1
                skipfish -o $1_80 http://$1 > /fichero 2>&1
                cd ..
		echo -e "\e[0;34m[+]  Skipfish analysis done, report stored in" $1"_80 folder\e[0m"
		
	else
		#80 no open"
		echo -e "\e[0;34m[+]  80/tcp port not seems to be opened\e[0m"
	fi
	variable=`grep "Ports:" $1/$1_webapp.txt | cut -d ":" -f 3 | cut -d "/" -f 8,9 | cut -d " " -f 2`
	if [ $variable = "443/open" ]
                then
                #443 open"
		dirb443="1"
                echo -e "\e[1;35m[+]  443/tcp port detected as open\e[0m"
                echo -e "\e[0;34m[+]  Executing Nikto scanner on 443/tcp port...\e[0m"
		touch $1/$1_nikto443.txt
                nikto -h $1:443 > $1/$1_nikto443.txt
                echo -e "\e[0;34m[+]  Nikto analysis done\e[0m"
		echo -e "\e[0;34m[+]  Executing Skipfish scanner on 443/tcp port...\e[0m"
		cd $1
		skipfish -o $1_443 https://$1 > /fichero 2>&1
		cd ..
		echo -e "\e[0;34m[+]  Skipfish analysis done, report stored in" $1"_443 folder\e[0m"

        else
                #443 no open"
                echo -e "\e[0;34m[+]  443/tcp port not seems to be opened\e[0m"
        fi
	variable=`grep "open" $1/$1_webapp.txt | cut -d "," -f 3 | cut -d " " -f 2 | cut -d "/" -f 1,2`
        if [ $variable = "8000/open" ]
                then
                #8000 open"
                echo -e "\e[1;35m[+]  8000/tcp port detected as open\e[0m"
                echo -e "\e[0;34m[+]  Executing Nikto scanner on 8000/tcp port...\e[0m"
		touch $1/$1_nikto8000.txt
                nikto -h $1:8000 > $1/$1_nikto8000.txt
                echo -e "\e[0;34m[+]  Nikto analysis done\e[0m"
		echo -e "\e[0;34m[+]  Executing Skipfish scanner on 8000/tcp port...\e[0m"
                cd $1
                skipfish -o $1_8000 http://$1:8000 > /fichero 2>&1
                cd ..
                echo -e "\e[0;34m[+]  Skipfish analysis done, report stored in" $1"_8000 folder\e[0m"

        else
                #8000 no open"
                echo -e "\e[0;34m[+]  8000/tcp port not seems to be opened\e[0m"
        fi
	variable=`grep "Ports:" $1/$1_webapp.txt | cut -d ":" -f 3 | cut -d "," -f 4 | cut -d " " -f 2 | cut -d "/" -f 1,2`
        if [ $variable = "8080/open" ]
                then
                #8080 open"
                echo -e "\e[1;35m[+]  8080/tcp port detected as open\e[0m"
                echo -e "\e[0;34m[+]  Executing Nikto scanner on 8080/tcp port...\e[0m"
		touch $1/$1_nikto8080.txt
                nikto -h $1:8080 > $1/$1_nikto8080.txt
                echo -e "\e[0;34m[+]  Nikto analysis done\e[0m"
		echo -e "\e[0;34m[+]  Executing Skipfish scanner on 8080/tcp port...\e[0m"
                cd $1
                skipfish -o $1_8080 http://$1:8080 > /fichero 2>&1
                cd ..
                echo -e "\e[0;34m[+]  Skipfish analysis done, report stored in" $1"_8080 folder\e[0m"

        else
                #8080 no open"
                echo -e "\e[0;34m[+]  8080/tcp port not seems to be opened\e[0m"
        fi


fi

# Fuzzing web directories with dirb

if [ $dirb = "1" ]
	then
	cd $1
	echo -e "\e[0;34m[+]  Fuzzing web directories with dirb on 80/tcp port\e[0m"
	dirb http://$1 /root/Documents/pentest/fuzzers/wordlist/raft-large-directories.txt -w -N 400 -o $1_directories_80.txt > /fichero 2>&1
	echo -e "\e[0;34m[+]  Fuzzing step finished\e[0m"
	cd ..
fi

if [ $dirb443 = "1" ]
        then
        cd $1
        echo -e "\e[0;34m[+]  Fuzzing web directories with dirb on 443/tcp port\e[0m"
        dirb https://$1 /root/Documents/pentest/fuzzers/wordlist/raft-large-directories.txt -w -N 400 -o $1_directories_443.txt > /fichero 2>&1
        echo -e "\e[0;34m[+]  Fuzzing step finished\e[0m"
        cd ..
fi


echo -e "\e[0;34m[+]  Analysis finished at" `date`  "\e[0m"
rm $1/$1_webapp.txt
