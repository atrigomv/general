#!/bin/bash

##############################################################################################################################################

##	Description: Kali fingerprint script

##	Version: 0.3

##	Basic usage: ./finger2.sh <ip>

##	Author: Alvaro Trigo

#############################################################################################################################################

echo ""
echo -e "\e[0;34m[+]  finger.sh v0.3 by Alvaro Trigo \e[0m"
echo -e "\e[0;34m[+]  Starting fingerprint at" `date`  "\e[0m"
echo -e "\e[0;34m[+]  The target host has the follow IP:" $1 "\e[0m"

# Scanner options

flag_nmap="0"
flag_smb="1"
flag_rdp="1"
flag_kerberos="1"
flag_ssh="1"
flag_ftp="1"
flag_web_dirb="0"
flag_web_gobuster="1"
flag_web_vhost="0"
flag_web_skipfish="1"

# Creating flags

flagA="0"
flagB="0"

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

if [ $flag_nmap = "1" ]
	then
	echo -e "\e[0;34m[+]  Starting NMAP scan... \e[0m"
	nmap -sT -sV -A -O -p1-65535 $1 -oA $1/$1_nmap -T4 > /fichero 2>&1
else
	echo -e "\e[0;34m[+]  Starting NMAP scan (express mode)... \e[0m"
	nmap -sT -F $1 -oA $1/$1_nmap -T5 > /fichero 2>&1
fi
echo -e "\e[0;34m[+]  NMAP scan done \e[0m"

########### SMB SCAN MODULE ###########

variable=`grep 'portid="445"><state state="open"' $1/$1_nmap.xml`
if [ -n "$variable" ] && [ $flag_smb = "1" ]
	then
	echo -e "\e[1;35m[+]  SMB service detected!\e[0m"
	variable=`grep 'portid="445"><state state="open"' $1/$1_nmap.xml | cut -d "<" -f 4 | cut -d "=" -f 3 | cut -d '"' -f 2`
	echo -e "\e[0;34m[+]  The target is a" $variable"\e[0m"
	variable=`grep '<elem key="domain_dns">' $1/$1_nmap.xml | cut -d ">" -f 2 | cut -d "<" -f 1`
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
        enum4linux -a $1 > $1/$1_smb_nullsession.txt
        variable=`grep "Aborting remainder of tests." $1/$1_smb_nullsession.txt`
        if [ -z "$variable" ]
                then
                echo -e "\e[0;34m[+]  Null session enumeration done!\e[0m"
        else
                echo -e "\e[0;34m[+]  The enumeration was not possible\e[0m"
        fi
else
	if [ $flag_smb = "1" ]
		then
		echo -e "\e[0;34m[+]  No SMB service detected\e[0m"
	fi
fi

########### RDP SCAN MODULE ###########

variable=`grep 'portid="3389"><state state="open"' $1/$1_nmap.xml`
if [ -n "$variable" ] && [ $flag_rdp = "1" ]
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
	if [ $flag_rdp = "1" ]
		then
		echo -e "\e[0;34m[+]  No RDP service detected\e[0m"
	fi
fi

########### KERBEROS SCAN MODULE ###########

variable=`grep 'portid="88"><state state="open"' $1/$1_nmap.xml`
if [ -n "$variable" ] && [ $flag_kerberos = "1" ]
	then
	echo -e "\e[1;35m[+]  Kerberos service detected!\e[0m"
	if [ $flagA = "1" ]
		then
		flagA="0"
		echo -e "\e[0;34m[+]  Enumerate valid Domain Users via Kerberos...\e[0m"
		variable=`grep '<elem key="domain_dns">' $1/$1_nmap.xml | cut -d ">" -f 2 | cut -d "<" -f 1`
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
	if [ $flag_kerberos = "1" ]
		then
		echo -e "\e[0;34m[+]  No Kerberos service detected\e[0m"
	fi
fi

########### SSH SCAN MODULE ###########

variable=`grep 'portid="22"><state state="open"' $1/$1_nmap.xml`
if [ -n "$variable" ] && [ $flag_ssh = "1" ]
	then
	echo -e "\e[1;35m[+]  SSH service detected!\e[0m"
	variable=`grep 'portid="22"><state state="open"' $1/$1_nmap.xml | cut -d "<" -f 4 | cut -d '=' -f 4 | cut -d " " -f 1 | cut -d '"' -f 2`
	echo -e "\e[0;34m[+]  Version: OpenSSH "$variable". Looking for known exploits in searchsploit...\e[0m"
	touch $1/$1_ssh_exploits.txt
	searchsploit OpenSSH $variable > $1/$1_ssh_exploits.txt
	variable=`grep "Exploits: No Result" $1/$1_ssh_exploits.txt`
	if [ -n "$variable" ]
		then
		echo -e "\e[0;34m[+]  Not known exploits found\e[0m"
	else
		echo -e "\e[1;32m[+]  Known exploits found! Please, check ssh_exploits.txt file\e[0m"
	fi
	echo -e "\e[0;34m[+]  Looking for 'root' user...\e[0m"
	msfconsole -q -o $1/$1_ssh_rootuser.txt -x "use auxiliary/scanner/ssh/ssh_enumusers;\
	set RHOSTS $1;\
	set USERNAME root;\
	run;\
	quit"
	variable=`grep "found" $1/$1_ssh_rootuser.txt`
	if [ -n "$variable" ]
		then
		echo -e "\e[0;34m[+]  'root' user found\e[0m"
		rm -f $1/$1_ssh_rootuser.txt
		echo -e "\e[0;34m[+]  Brute forcing 'root' user with 200 most common passwords...\e[0m"
		hydra -l root -P /root/Documentos/pentest/fuzzers/wordlist/top200_passwords.txt $1 -t4 ssh > $1/$1_ssh_200pass.txt
		variable=`grep "0 valid passwords found" $1/$1_ssh_200pass.txt`
		if [ -n "$variable" ]
			then
			echo -e "\e[0;34m[+]  No password found for 'root' user \e[0m"
		else
			echo -e "\e[1;32m[+]  Possible password for 'root' user found. Please, check ssh_200pass.txt file\e[0m"
		fi
		echo -e "\e[0;34m[+]  Brute forcing 'root' user with 200 first entries of rockyou file...\e[0m"
		hydra -l root -P /root/Documentos/pentest/fuzzers/wordlist/200_rockyou.txt $1 -t4 ssh > $1/$1_ssh_200passrockyou.txt
		variable=`grep "0 valid passwords found" $1/$1_ssh_200passrockyou.txt`
                if [ -n "$variable" ]
                        then
                        echo -e "\e[0;34m[+]  No password found for 'root' user \e[0m"
                else
                        echo -e "\e[1;32m[+]  Possible password for 'root' user found. Please, check ssh_200passrockyou.txt file\e[0m"
                fi
	else
		echo -e "\e[0;34m[+]  'root' user not found\e[0m"
	fi
else
	if [ $flag_ssh = "1" ]
		then
		echo -e "\e[0;34m[+]  No SSH service detected\e[0m"
	fi
fi

########### FTP SCAN MODULE ###########

variable=`grep 'portid="21"><state state="open"' $1/$1_nmap.xml`
if [ -n "$variable" ] && [ $flag_ftp = "1" ]
        then
        echo -e "\e[1;35m[+]  FTP service detected!\e[0m"
	flagA=`grep 'portid="21"><state state="open"' $1/$1_nmap.xml | cut -d "<" -f 4 | cut -d "=" -f 3 | cut -d '"' -f 2`
	flagB=`grep 'portid="21"><state state="open"' $1/$1_nmap.xml | cut -d "<" -f 4 | cut -d "=" -f 4 | cut -d '"' -f 2 | cut -d " " -f 1`
	variable="${flagA} ${flagB}"
	echo -e "\e[0;34m[+]  FTP Version: " $variable". Looking for known exploits in searchsploit...\e[0m"
	touch $1/$1_ftp_exploits.txt
	searchsploit $variable > $1/$1_ftp_exploits.txt
	variable=`grep "Exploits: No Result" $1/$1_ftp_exploits.txt`
	if [ -n "$variable" ]
		then
		echo -e "\e[0;34m[+]  No exploits found for ${flagA} ${flagB}. Looking for ${flagA} exploits without version...\e[0m"
		rm -f $1/$1_ftp_exploits.txt
		searchsploit $flagA > $1/$1_ftp_exploits.txt
		variable=`grep "Exploits: No Result" $1/$1_ftp_exploits.txt`
		if [ -n "$variable" ]
			then
			echo -e "\e[0;34m[+]  Not known exploits found\e[0m"
		else
			echo -e "\e[1;32m[+]  Known exploits found (some versions of ${flagA} affected) but probably does not work. Please, check ftp_exploits.txt file\e[0m"
		fi
	else
		echo -e "\e[1;32m[+]  Known exploits found! Please, check ftp_exploits.txt file\e[0m"
	fi
	flagA="0"
	flagB="0"

	echo -e "\e[0;34m[+]  Trying anonymous login...\e[0m"

	msfconsole -q -o $1/$1_ftp_anonymous.txt -x "use auxiliary/scanner/ftp/anonymous;\
	set RHOSTS $1;\
	run;\
	quit"
	variable=`grep " Anonymous" $1/$1_ftp_anonymous.txt`
	if [ -n "$variable" ]
		then
		variable=`grep " Anonymous" $1/$1_ftp_anonymous.txt | cut -d "-" -f 3`
		echo -e "\e[1;32m[+]  Anonymous access allowed: " $variable"\e[0m"
	else
		echo -e "\e[0;34m[+]  No anonymous access allowed\e[0m"
	fi

	echo -e "\e[0;34m[+]  Brute forcing 'root' user with 200 most common passwords...\e[0m"
	hydra -l root -P /root/Documentos/pentest/fuzzers/wordlist/top200_passwords.txt $1 ftp > $1/$1_ftp_200pass.txt
	variable=`grep "0 valid passwords found" $1/$1_ftp_200pass.txt`
	if [ -n "$variable" ]
		then
		echo -e "\e[0;34m[+]  No password found for 'root' user \e[0m"
	else
		echo -e "\e[1;32m[+]  Possible password for 'root' user found. Please, check ftp_200pass.txt file\e[0m"
	fi
	echo -e "\e[0;34m[+]  Brute forcing 'root' user with 200 first entries of rockyou file...\e[0m"
	hydra -l root -P /root/Documentos/pentest/fuzzers/wordlist/200_rockyou.txt $1 ftp > $1/$1_ftp_200passrockyou.txt
	variable=`grep "0 valid passwords found" $1/$1_ftp_200passrockyou.txt`
	if [ -n "$variable" ]
		then
		echo -e "\e[0;34m[+]  No password found for 'root' user \e[0m"
	else
		echo -e "\e[1;32m[+]  Possible password for 'root' user found. Please, check ftp_200passrockyou.txt file\e[0m"
	fi
else
	if [ $flag_ftp = "1" ]
		then
		echo -e "\e[0;34m[+]  No FTP service detected\e[0m"
	fi
fi

########### WEB SCAN MODULE ###########

variable=`grep 'portid="80"><state state="open"' $1/$1_nmap.xml`
if [ -n "$variable" ]
	then
	echo -e "\e[1;35m[+]  Web application detected on 80/tcp port!\e[0m"
	if [ $flag_web_dirb = "1" ]
		then
		echo -e "\e[0;34m[+]  Fuzzing web directories with dirb on 80/tcp port (raft-large-directories dictionary)\e[0m"
		cd $1
		dirb http://$1 /root/Documentos/pentest/fuzzers/wordlist/raft-large-directories.txt -w -N 400 -o $1_web_directories_dirb_80.txt > /fichero 2>&1
		cd ..
		echo -e "\e[0;34m[+]  Fuzzing finished\e[0m"
	fi
	if [ $flag_web_gobuster = "1" ]
		then
		echo -e "\e[0;34m[+]  Fuzzing web directories with gobuster on 80/tcp port (dirbuster directory-list-medium dictionary)\e[0m"
		gobuster dir -k -q -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" -t 18 -u http://$1 --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o $1/$1_web_directories_gobuster_80.txt
		echo -e "\e[0;34m[+]  Fuzzing finished\e[0m"
	fi
	if [ $flag_web_vhost = "1" ]
		then
		echo -e "\e[0;34m[+]  Fuzzing vhost entries on 80/tcp port (mode 1: <directory>.$1)\e[0m"
		gobuster vhost -k -q -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" -t 18 -u http://$1 -w /root/Documentos/pentest/fuzzers/wordlist/vhosts.list -o $1/$1_web_vhost_ip_80.txt
		echo -e "\e[0;34m[+]  Fuzzing finished\e[0m"
		variable=`grep '<elem key="commonName">' $1/$1_nmap.xml | cut -d ">" -f 2 | cut -d "<" -f 1 | head -1`
		if [ -n "$variable" ]
			then
			echo -e "\e[0;34m[+]  Fuzzing vhost entries on 80/tcp port (mode 2: <directory>.$variable)\e[0m"
			gobuster vhost -k -z -q -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" -t 18 -u http://$variable -w /root/Documentos/pentest/fuzzers/wordlist/vhosts.list -o $1/$1_web_vhost_commonname_443.txt
			echo -e "\e[0;34m[+]  Fuzzing finished\e[0m"
		fi
		variable=`grep '<elem key="emailAddress">' $1/$1_nmap.xml | cut -d ">" -f 2 | cut -d "<" -f 1 | cut -d "@" -f 2 | head -1`
		if [ -n "$variable" ]
			then
			echo -e "\e[0;34m[+]  Fuzzing vhost entries on 80/tcp port (mode 3: <directory>.$variable)\e[0m"
			gobuster vhost -k -z -q -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" -t 18 -u http://$variable -w /root/Documentos/pentest/fuzzers/wordlist/vhosts.list -o $1/$1_web_vhost_emaildomain_80.txt
			echo -e "\e[0;34m[+]  Fuzzing finished\e[0m"
		fi
	fi
	echo -e "\e[0;34m[+]  Executing Nikto scanner on 80/tcp port...\e[0m"
	touch $1/$1_web_nikto80.txt
	nikto -maxtime 15m -no404 -C all -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" -h http://$1 > $1/$1_web_nikto80.txt
	echo -e "\e[0;34m[+]  Nikto analysis done\e[0m"
	if [ $flag_web_skipfish = "1" ]
		then
		echo -e "\e[0;34m[+]  Executing Skipfish scanner on 80/tcp port...\e[0m"
		cd $1
		skipfish -o $1_80 http://$1 > /fichero 2>&1
        	cd ..
        	echo -e "\e[0;34m[+]  Skipfish analysis done, report stored in" $1"_80 folder\e[0m"
	fi
else
	echo -e "\e[0;34m[+]  No web application detected on 80/tcp port\e[0m"
fi


variable=`grep 'portid="443"><state state="open"' $1/$1_nmap.xml`
if [ -n "$variable" ]
	then
	echo -e "\e[1;35m[+]  Web application detected on 443/tcp port!\e[0m"
	if [ $flag_web_dirb = "1" ]
		then
		echo -e "\e[0;34m[+]  Fuzzing web directories with dirb on 443/tcp port (raft-large-directories dictionary)\e[0m"
		cd $1
		dirb https://$1 /root/Documentos/pentest/fuzzers/wordlist/raft-large-directories.txt -w -N 400 -o $1_web_directories_dirb_443.txt > /fichero 2>&1
		cd ..
		echo -e "\e[0;34m[+]  Fuzzing finished\e[0m"
	fi
	if [ $flag_web_gobuster = "1" ]
		then
		echo -e "\e[0;34m[+]  Fuzzing web directories with gobuster on 443/tcp port (dirbuster directory-list-medium dictionary)\e[0m"
		gobuster dir -k -q -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" -t 18 -u https://$1 --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o $1/$1_web_directories_gobuster_443.txt
		echo -e "\e[0;34m[+]  Fuzzing finished\e[0m"
	fi
	if [ $flag_web_vhost = "1" ]
		then
		echo -e "\e[0;34m[+]  Fuzzing vhost entries on 443/tcp port (mode 1: <directory>.$1)\e[0m"
		gobuster vhost -k -q -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" -t 18 -u https://$1 -w /root/Documentos/pentest/fuzzers/wordlist/vhosts.list -o $1/$1_web_vhost_ip_443.txt
		echo -e "\e[0;34m[+]  Fuzzing finished\e[0m"
		variable=`grep '<elem key="commonName">' $1/$1_nmap.xml | cut -d ">" -f 2 | cut -d "<" -f 1 | head -1`
		if [ -n "$variable" ]
			then
			echo -e "\e[0;34m[+]  Fuzzing vhost entries on 443/tcp port (mode 2: <directory>.$variable)\e[0m"
			gobuster vhost -k -z -q -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" -t 18 -u https://$variable -w /root/Documentos/pentest/fuzzers/wordlist/vhosts.list -o $1/$1_web_vhost_commonname_443.txt
			echo -e "\e[0;34m[+]  Fuzzing finished\e[0m"
		fi
		variable=`grep '<elem key="emailAddress">' $1/$1_nmap.xml | cut -d ">" -f 2 | cut -d "<" -f 1 | cut -d "@" -f 2 | head -1`
		if [ -n "$variable" ]
			then
			echo -e "\e[0;34m[+]  Fuzzing vhost entries on 443/tcp port (mode 3: <directory>.$variable)\e[0m"
			gobuster vhost -k -z -q -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" -t 18 -u https://$variable -w /root/Documentos/pentest/fuzzers/wordlist/vhosts.list -o $1/$1_web_vhost_emaildomain_443.txt
			echo -e "\e[0;34m[+]  Fuzzing finished\e[0m"
		fi
	fi
	echo -e "\e[0;34m[+]  Executing Nikto scanner on 443/tcp port...\e[0m"
	touch $1/$1_web_nikto443.txt
	nikto -maxtime 15m -no404 -C all -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36" -h https://$1 > $1/$1_web_nikto443.txt
	echo -e "\e[0;34m[+]  Nikto analysis done\e[0m"
	if [ $flag_web_skipfish = "1" ]
		then
		echo -e "\e[0;34m[+]  Executing Skipfish scanner on 443/tcp port...\e[0m"
		cd $1
		skipfish -o $1_443 https://$1 > /fichero 2>&1
		cd ..
		echo -e "\e[0;34m[+]  Skipfish analysis done, report stored in" $1"_443 folder\e[0m"
	fi
else
	echo -e "\e[0;34m[+]  No web application detected on 443/tcp port\e[0m"
fi

echo -e "\e[0;34m[+]  Analysis finished at" `date`  "\e[0m"
