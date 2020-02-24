#!/bin/bash

echo ""
echo -e "\e[0;34m[+]  finger.sh v0.3 by Alvaro Trigo \e[0m"
echo -e "\e[0;34m[+]  Starting fingerprint at" `date`  "\e[0m"
echo -e "\e[0;34m[+]  The target host has the follow IP:" $1 "\e[0m"

# Creating flag dirb

flagA="0"
dirb="0"
dirb443="0"

# Creating the results folder:

mkdir $1 > /fichero 2>&1

########### PING MODULE ###########

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

########### NMAP SCAN MODULE ###########

echo -e "\e[0;34m[+]  Starting NMAP scan... \e[0m"
#nmap -sT -sV -A -O -p1-65535 $1 -oA $1/$1_nmap -T4 > /fichero 2>&1
echo -e "\e[0;34m[+]  NMAP scan done \e[0m"

########### SMB SCAN MODULE ###########

echo -e "\e[0;34m[+]  SMB service detection...\e[0m"

variable=`grep 'portid="445"><state state="open"' /root/Escritorio/finger/prueba/10.10.10.161_nmap.xml`
if [ -n "$variable" ]
	then
	echo -e "\e[1;35m[+]  SMB service detected!\e[0m"
	variable=`grep 'portid="445"><state state="open"' /root/Escritorio/finger/prueba/10.10.10.161_nmap.xml | cut -d "<" -f 4 | cut -d "=" -f 3 | cut -d '"' -f 2`
	echo -e "\e[0;34m[+]  The target is a" $variable"\e[0m"
	variable=`grep '<elem key="domain_dns">' /root/Escritorio/finger/prueba/10.10.10.161_nmap.xml | cut -d ">" -f 2 | cut -d "<" -f 1`
	if [ -n "$variable" ]
		then
		echo -e "\e[0;34m[+]  Domain name:" $variable"\e[0m"
		flagA="1"
		else
		echo -e "\e[0;34m[+]  Domain name could not be retrieved \e[0m"
	fi

	echo -e "\e[0;34m[+]  Checking if the target is vulnerable to MS17-010 EthernalBlue...\e[0m"

	if [ $flagA = "1" ]
		then
		msfconsole -q -o $1/$1_smb_ethernalblue.txt -x "use exploit/windows/smb/ms17_010_eternalblue;\
		set RHOSTS $1;\
		set SMBDomain $variable;\
		check;\
		quit"
	else
		msfconsole -q -o $1/$1_smb_ethernalblue.txt -x "use exploit/windows/smb/ms17_010_eternalblue;\
		set RHOSTS $1;\
		check;\
		quit"
	fi
	variable=`grep "Host does NOT appear vulnerable" $1/$1_smb_ethernalblue.txt`
	if [ -n "$variable" ]
		then
		echo -e "\e[0;34m[+]  Host does NOT appear vulnerable to MS17-010 EthernalBlue \e[0m"
	else
		variable=`grep "Cannot reliably check exploitability" $1/$1_smb_ethernalblue.txt`
		if [ -n "$variable" ]
			then
			echo -e "\e[0;34m[+]  Host does NOT appear vulnerable to MS17-010 EthernalBlue \e[0m"
		else
			echo -e "\e[1;32m[+]  Host could be vulnerable to MS17-010 EthernalBlue! Manual check is required (use exploit/windows/smb/ms17_010_eternalblue) \e[0m"
		fi
	fi
	
	echo -e "\e[0;34m[+]  Checking if the target is vulnerable to MS08-06 Netapi...\e[0m"

        msfconsole -q -o $1/$1_smb_netapi.txt -x "use exploit/windows/smb/ms08_067_netapi;\
	set RHOSTS $1;\
	check;\
	quit"
	variable=`grep "The target is not exploitable" $1/$1_smb_netapi.txt`
	if [ -n "$variable" ]
		then
		echo -e "\e[0;34m[+]  Host does NOT appear vulnerable to MS08-067 Netapi \e[0m"
	else
		variable=`grep "Cannot reliably check exploitability" $1/$1_smb_netapi.txt`
		if [ -n "$variable" ]
			then
			echo -e "\e[0;34m[+]  Host does NOT appear vulnerable to MS08-067 Netapi \e[0m"
		else
			echo -e "\e[1;32m[+]  Host could be vulnerable to MS08-067 Netapi! Manual check is required (use exploit/windows/smb/ms08_067_netapi) \e[0m"
		fi
	fi

	echo -e "\e[0;34m[+]  Trying null session enumeration\e[0m"

        touch $1/$1_smb_nullsession.txt
        #enum4linux -a $1 > $1/$1_smb_nullsession.txt
        variable=`grep "Aborting remainder of tests." $1/$1_smb_nullsession.txt`
        if [ -z "$variable" ]
                then
                echo -e "\e[0;34m[+]  Null session enumeration done!\e[0m"
        else
                echo -e "\e[0;34m[+]  The enumeration was not possible\e[0m"
        fi
else
	echo -e "\e[0;34m[+]  No SMB service detected\e[0m"
fi

########### RDP SCAN MODULE ###########

echo -e "\e[0;34m[+]  RDP service detection...\e[0m"
variable=`grep 'portid="3389"><state state="open"' /root/Escritorio/finger/prueba/10.10.10.161_nmap.xml`
if [ -n "$variable" ]
	then
	echo -e "\e[1;35m[+]  RDP service detected!\e[0m"
	
	echo -e "\e[0;34m[+]  Checking if the target is vulnerable to BlueKeep vulnerability (cve2019-0708)...\e[0m"
	
	msfconsole -q -o $1/$1_rdp_bluekeep.txt -x "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce;\
        set RHOSTS $1;\
        check;\
        quit"
	variable=`grep "The target is not exploitable" $1/$1_rdp_bluekeep.txt`
	if [ -n "$variable" ]
		then
		echo -e "\e[0;34m[+]  Host does NOT appear vulnerable to Bluekeep vulnerability \e[0m"
	else
		variable=`grep "Cannot reliably check exploitability" $1/$1_rdp_bluekeep.txt`
		if [ -n "$variable" ]
			then
			echo -e "\e[0;34m[+]  Host does NOT appear vulnerable to Bluekeep vulnerability \e[0m"
		else
			echo -e "\e[1;32m[+]  Host could be vulnerable to Bluekeep vulnerability! Manual check is required (use exploit/windows/rdp/cve_2019_0708_bluekeep_rce) \e[0m"
		fi
	fi

	echo -e "\e[0;34m[+]  Checking if the target is vulnerable to MS12-020 DoS vulnerability...\e[0m"
	
	msfconsole -q -o $1/$1_rdp_ms12-020_DoS.txt -x "use auxiliary/scanner/rdp/ms12_020_check;\
	set RHOSTS $1;\
	run;\
	quit"
else
	echo -e "\e[0;34m[+]  No RDP service detected\e[0m"
fi

########### KERBEROS SCAN MODULE ###########

echo -e "\e[0;34m[+]  Kerberos service detection...\e[0m"
variable=`grep 'portid="88"><state state="open"' /root/Escritorio/finger/prueba/10.10.10.161_nmap.xml`
if [ -n "$variable" ]
	then
	echo -e "\e[1;35m[+]  Kerberos service detected!\e[0m"
	if [ $flagA = "1" ]
		then
		flagA="0"
		echo -e "\e[0;34m[+]  Enumerate valid Domain Users via Kerberos...\e[0m"
		variable=`grep '<elem key="domain_dns">' /root/Escritorio/finger/prueba/10.10.10.161_nmap.xml | cut -d ">" -f 2 | cut -d "<" -f 1`
		msfconsole -q -o $1/$1_kerberos_enumusers_raw.txt -x "use auxiliary/gather/kerberos_enumusers;\
		set RHOSTS $1;\
		set DOMAIN $variable;\
		set USER_FILE /root/Documentos/pentest/fuzzers/wordlist/win_usernames.txt;\
		run;\
		quit"
		variable=`grep "is present" $1/$1_kerberos_enumusers_raw.txt`
		if [ -n "$variable" ]
			then
			echo -e "\e[1;32m[+]  Domain Users found! Please, check kerberos_users.txt file\e[0m"
			touch $1/$1_kerberos_users.txt
			cat $1/$1_kerberos_enumusers_raw.txt | grep "is present" > $1/$1_kerberos_users.txt
		else
			echo -e "\e[0;34m[+]  No Domain Users found\e[0m"
		fi
	else
		echo -e "\e[0;34m[+]  Host domain name could not be retrieved. Aborting enum Kerberos users\e[0m"
	fi
else
	echo -e "\e[0;34m[+]  No Kerberos service detected\e[0m"
fi
