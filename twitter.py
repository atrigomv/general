#!/usr/bin/python

import tweepy, smtplib


print ''
print 'OoOoOoOoOoOoOoOoOoOoOoOoOo'
print 'O                        O'
print 'O    Twitter Scanner     O'
print 'O                        O'
print 'OoOoOoOoOoOoOoOoOoOoOoOoOo'
print ''  

# Definicion de cuentas a seguir

cuentas = ['Pablo_Iglesias_', 'ahorapodemos', 'sipodemos2014', 'AnonymousAction', 'AnonymousEspana', 'anonspain', 'Anononspain', 'AnonSpainloic', 'IberoAnon', 'JSE_ORG', 'ujcemadrid', 'ujce', 'CJCMadrid_']

# Definicion de palabras a buscar (en minusculas)
# palLevel0: palabras que por si solas son riesgo MEDIO
# palLevel1: palabras que por si solas son riesgo BAJO
# palLevel2: palabras que por si solas no suponen riesgo pero que unidas a alguna de las otras dos son riesgo ALTO

palLevel0 = ['joaquin lopez', 'jose rico']
palLevel1 = ['dioces', 'sacerdote', 'monja', 'parroq', 'vatican', 'obispo', 'papa', 'prelado', 'monaguillo', 'curia']
palLevel2 = ['ataque', 'manifestacion', 'protesta', 'scratch', 'tamborrada', 'persecuci', 'quema', 'concentra', 'attack', 'matar', 'asesin', 'repeler', 'rodea'] 

# Credenciales Twitter

consumer_key = ''
consumer_secret = ''
access_token = ''
access_token_secret = ''

# Proceso de autenciacion en Twitter

print 'Autenticando en Twitter...'
auth = tweepy.auth.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)
api = tweepy.API(auth)
print 'Autenticacion finalizada.'

# Sacar tweets de cuentas

for cuenta in cuentas:
	user = api.get_user(cuenta, include_entities=1)
	tweets = api.user_timeline(id=cuenta, include_rts=True, count = 5)
	print ''
	print '[+] User: ' + user.name + ' (@' + str(user.screen_name) + ')' 
	print ''
	for tweet in tweets:
		flag=0
		publicacion = tweet.text.encode('UTF-8','ignore')	  
		for palabra0 in palLevel0:
			if (publicacion.lower().find(palabra0)!=-1):
				risk = 80
				flag = 1
				for palabra2 in palLevel2:
                                        if publicacion.lower().find(palabra2)!=-1:
                                                risk=100
                                print '[+][+] ' + publicacion + ' (' + str(tweet.created_at) + ') RISK: ' + str(risk)
		if flag!=1:
			for palabra1 in palLevel1:
				if publicacion.lower().find(palabra1)!=-1:
					flag = 1
					risk = 50
					for palabra2 in palLevel2:
						if publicacion.lower().find(palabra2)!=-1:
							risk=100
					print '[+][+] ' + publicacion + ' (' + str(tweet.created_at) + ') RISK: ' + str(risk)
			if flag!=1:
				if publicacion.lower().find('iglesia')!=-1:
					if publicacion.lower().find('iglesias')==-1:
						risk=50
						for palabra2 in palLevel2:
		                                	       if publicacion.lower().find(palabra2)!=-1:
                		                        	       risk=100
                               			print '[+][+] ' + publicacion + ' (' + str(tweet.created_at) + ') RISK: ' + str(risk)
