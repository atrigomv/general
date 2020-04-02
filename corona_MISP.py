import sys
import urllib3

# 1. Variables

file_IOC_path = 'C:/Users/atrigom/Desktop/IOC_hashes.txt'
file_md5 = 'C:/Users/atrigom/Desktop/md5_no.txt'
file_sha1 = 'C:/Users/atrigom/Desktop/sha1_no.txt'
file_sha2 = 'C:/Users/atrigom/Desktop/sha2_no.txt'
cont_hashes = 0
cont_hashes_sha1 = 0
cont_hashes_sha2 = 0
cont_hashes_md5 = 0
cont_hashes_otros = 0

list_sha1 = []
list_sha2 = []
list_md5 = []
list_otros = []

misp_url = '<MISP_URL>'
key = '<YOUR_MISP_API_KEY>'
time = '2d'

#url_CCN = 'https://loreto.ccn-cert.cni.es/index.php/s/oDcNr5Jqqpd5cjn/download?path=%2F&files=IOC_hashes.txt'

# 2. Retrieving hashes from CCN file

print('[+] Retrieving hashes from file ' + file_IOC_path + '...')
f = open(file_IOC_path, 'r')
while(True):
    try:
        linea = f.readline()
    except:
        print('[-] Error retrieving data from file ' + file_IOC_path)
        sys.exit(0)
    if(not linea):
        break
    cont_hashes = cont_hashes + 1
    if(len(linea) == 65 or len(linea) == 64):
        cont_hashes_sha2 = cont_hashes_sha2 + 1
        if(len(linea) == 65):
            list_sha2.append(linea[:(len(linea)-1)])
        else:
            list_sha2.append(linea)
    else:
        if(len(linea) == 41 or len(linea) == 40):
            cont_hashes_sha1 = cont_hashes_sha1 + 1
            if(len(linea) == 41):
                list_sha1.append(linea[:(len(linea)-1)])
            else:
                list_sha1.append(linea)
        else:
            if(len(linea) == 33 or len(linea) == 32):
                cont_hashes_md5 = cont_hashes_md5 + 1
                if(len(linea) == 33):
                    list_md5.append(linea[:(len(linea)-1)])
                else:
                    list_md5.append(linea)
            else:
                cont_hashes_otros = cont_hashes_otros + 1
                list_otros.append(linea)
f.close()
print('[+] ' + str(cont_hashes) + ' total hashes retrieved: ' + str(cont_hashes_sha2) + ' SHA-256 hashes, ' + str(cont_hashes_sha1) + ' SHA-160 hashes, ' + str(cont_hashes_md5) + ' MD5 hashes and ' + str(cont_hashes_otros) + ' unknown hashes.')

# 3. Retrieving MD5 hashes from MISP

print('[+] Retrieving MD5 hashes from MISP server...')
url = 'https://' + misp_url + '/events/hids/md5/download/false/false/false/' + time
headers = {'Accept': 'application/json', 'Content-type': 'application/json', 'Authorization': key}

http = urllib3.PoolManager()
r = http.request('GET',url,headers=headers)
values = r.data.decode()
lista = list(values.split('\n'))

print('[+] Matching CCN hashes with MISP server...')
cont_hashes = 0
for ccn_ioc in list_md5:
    if(ccn_ioc in lista):
        cont_hashes = cont_hashes + 1
    else:
        f = open(file_md5,'a')
        f.write(ccn_ioc + '\n')
        f.close()
print('[+] ' + str(cont_hashes) + ' of ' + str(cont_hashes_md5) + ' MD5 hashes found in MISP')

# 4. Retrieving SHA-1 hashes from MISP

print('[+] Retrieving SHA-1 hashes from MISP server...')
lista = []
url = 'https://' + misp_url + '/events/hids/sha1/download/false/false/false/' + time
headers = {'Accept': 'application/json', 'Content-type': 'application/json', 'Authorization': key}

http = urllib3.PoolManager()
r = http.request('GET',url,headers=headers)
values = r.data.decode()
lista = list(values.split('\n'))

print('[+] Matching CCN hashes with MISP server...')
cont_hashes = 0
for ccn_ioc in list_sha1:
    if(ccn_ioc in lista):
        cont_hashes = cont_hashes + 1
    else:
        f = open(file_sha1,'a')
        f.write(ccn_ioc + '\n')
        f.close()
print('[+] ' + str(cont_hashes) + ' of ' + str(cont_hashes_sha1) + ' SHA-1 hashes found in MISP')

# 5. Retrieving SHA-256 hashes from MISP

print('[+] Retrieving SHA-256 hashes from MISP server...')
lista = []
url = 'https://' + misp_url + '/attributes/text/download/sha256/false/false/false/false/false/' + time
headers = {'Accept': 'application/json', 'Content-type': 'application/json', 'Authorization': key}

http = urllib3.PoolManager()
r = http.request('GET',url,headers=headers)
values = r.data.decode()
lista = list(values.split('\n'))


print('[+] Matching CCN hashes with MISP server...')
cont_hashes = 0
for ccn_ioc in list_sha2:
    if(ccn_ioc in lista):
        cont_hashes = cont_hashes + 1
    else:
        f = open(file_sha2,'a')
        f.write(ccn_ioc + '\n')
        f.close()
print('[+] ' + str(cont_hashes) + ' of ' + str(cont_hashes_sha2) + ' SHA-256 hashes found in MISP')