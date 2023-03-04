#!/usr/bin/env python
#--coding:utf-8--

import http.server
import http.cookies
import json, time, base64, urllib
import paramiko

import config



#config
# Server
LISTEN_ADDR				= '127.0.0.1'
LISTEN_PORT				= 8880

# Redirect
REDIRECT_CODE			= 307
REDIRECT_URL			= 'https://nas.yourdomain.com:1443'

# Security header converted to get parameter sent.
REDIRECT_HEADER_TO_GET	= True
REDIRECT_HEADERS		= ['Authorization', 'WWW-Authenticate', 'Cookie', 'Cookie2']

# Auth method
AUTH_TYPE				= 'NONE'				# 'NONE', 'BASIC', 'GET', 'POST', 'COOKIE', 'HEADER'

# for BASIC
AUTH_USER				= 'proxy-knocker'
AUTH_PASS				= 'passwd'

# for GET/POST/COOKIE/HEADER
AUTH_FIELD				= 'proxy-knocker'
AUTH_KEY				= 'passwd'

# SSH
SSH_ADDR				= '127.0.0.1'
SSH_PORT				= 22
SSH_USER				= 'root'
SSH_PASS				= 'passwd'

# iptables
IPTABLES_PORT			= 1443

IPTABLES_APPEND			= 'sudo iptables -v -A INPUT -s {IP} -p tcp --dport ' + str(IPTABLES_PORT) + ' -j ACCEPT'
IPTABLES_DELETE			= 'sudo iptables -v -D INPUT -s {IP} -p tcp --dport ' + str(IPTABLES_PORT) + ' -j ACCEPT'
IPTABLES_CONFIRM		= 'sudo iptables -L -n | grep ' + str(IPTABLES_PORT) + ' | grep ACCEPT | grep {IP} | wc -l'






class ProxyKnockerServerHandler(http.server.BaseHTTPRequestHandler):
	def do_HEAD(self):
		self.send_response(200)
		self.send_header('Content-type', 'application/json')
		self.end_headers()

	def do_AUTHHEAD(self):
		self.send_response(401)
		self.send_header('WWW-Authenticate', 'Basic realm="Proxy-Knocker Realm"')
		self.send_header('Content-type', 'application/json')
		self.end_headers()
		
	def do_GET(self):
		self.do_main()

	def do_POST(self):
		self.do_main()

	def do_main(self):
		if self.do_auth() == False:
			self.send_error(401, 'Authentication failed');
			return

		client_ip, client_port = self.client_address

		if self.headers.get('X-Real-IP') != None:
			client_ip = self.headers.get('X-Real-IP')

		if self.do_iptable_confirm(client_ip) == True:
			pass
		else:
			self.do_iptable_append(client_ip)

		self.do_redirect()

	def do_iptable_append(self, client_ip):
		command = IPTABLES_APPEND.replace('{IP}', client_ip)
		response = self.do_ssh_exec(command)

		return response

	def do_iptable_delete(self, client_ip):
		command = IPTABLES_DELETE.replace('{IP}', client_ip)
		response = self.do_ssh_exec(command)

		return response

	def do_iptable_confirm(self, client_ip):
		command = IPTABLES_CONFIRM.replace('{IP}', client_ip)
		response = self.do_ssh_exec(command)

		if int(response) == 0:
			return False

		return True

	def do_ssh_exec(self, command):
		if self.server.ssh_client.get_transport().is_active() == False:
			print('[WARN] SSH session not active, Reconnecting...')

			if self.server.connect_ssh() == False:
				print('[ERR] SSH reconnect failed.')

				return False

		try:
			stdin, stdout, stderr = self.server.ssh_client.exec_command(command, timeout=5)
			response = stdout.read().decode('utf-8')

			return response
		except TimeoutError as err:
			raise err
		else:
			print('[ERR] SSH exec failed.')

			return False


	def do_auth(self):
		if AUTH_TYPE == 'BASIC':
			auth_key = base64.b64encode(bytes('%s:%s' % (AUTH_USER, AUTH_PASS), 'utf-8')).decode('ascii')

			if self.headers.get('Authorization') == 'Basic ' + str(auth_key):
				return True
			elif self.headers.get('Authorization') == None:
				self.do_AUTHHEAD()

				response = {
					'success': False,
					'error': 'No auth header received'
				}

				self.wfile.write(bytes(json.dumps(response), 'utf-8'))
			else:
				self.do_AUTHHEAD()

				response = {
					'success': False,
					'error': 'Invalid credentials'
				}

				self.wfile.write(bytes(json.dumps(response), 'utf-8'))

		elif AUTH_TYPE == 'GET':
			# TODO...
			pass
		elif AUTH_TYPE == 'POST':
			# TODO...
			pass
		elif AUTH_TYPE == 'COOKIE':
			cookies = http.cookies.SimpleCookie(self.headers.get('Cookie'))

			if AUTH_FIELD in cookies and cookies[AUTH_FIELD].value == AUTH_KEY:
				return True

		elif AUTH_TYPE == 'HEADER':
			if self.headers.get(AUTH_FIELD) == AUTH_KEY:
				return True
		elif AUTH_TYPE == 'NONE':
			return True
		else:
			pass

		return False

	def do_redirect(self):
		'''
		When the forwarded request contains secure information headers, such as Authorization, WWW-Authenticate,
		Cookie and other headers, if they are cross domain, these headers will not be copied to the new request.

		Therefore, when these headers are included in the request, change them to get parameter to send follow redirection,
		and then convert them to headers on nginx of receiving server.
		'''

		path = self.path

		if REDIRECT_HEADER_TO_GET:
			append_args = {}

			for headerKey in REDIRECT_HEADERS:
				if headerKey in self.headers:
					append_args['HTTP_' + headerKey] = self.headers.get(headerKey)

			if len(append_args) > 0:
				append_args = urllib.parse.urlencode(append_args)
				urlparse = urllib.parse.urlparse(self.path)

				if len(urlparse.query) == 0:
					path = self.path + '?' + append_args
				else:
					path = self.path + '&' + append_args

		self.send_response(REDIRECT_CODE)
		self.send_header('Location', REDIRECT_URL + path)
		self.end_headers()


class ProxyKnockerHTTPServer(http.server.HTTPServer):
	def __init__(self, address, handlerClass=ProxyKnockerServerHandler):
		super().__init__(address, handlerClass)

		self.ssh_client = None

	def __del__(self):
		if self.ssh_client:
			self.ssh_client.close()

		self.shutdown()

	def connect_ssh(self):
		if self.ssh_client == None:
			self.ssh_client = paramiko.SSHClient()
			self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		print('Connect SSH %s@%s:%s' % (SSH_USER, SSH_ADDR, SSH_PORT))

		try:
			self.ssh_client.connect(SSH_ADDR, port = SSH_PORT, username = SSH_USER, password = SSH_PASS, timeout = 10)

			print('Connect SSH Success.')

			return True
		except Exception as e:
			print('Connect SSH error: %s' % e)

			return False

def ProxyKnocker():
	httpd = ProxyKnockerHTTPServer((LISTEN_ADDR, LISTEN_PORT))

	if httpd.connect_ssh():
		print('Proxy-Knocker Listening: %s:%s' % (LISTEN_ADDR, LISTEN_PORT))
		print('Proxy-Knocker Redirect URL: %s' % REDIRECT_URL)
		print('Proxy-Knocker Authentication method: %s' % AUTH_TYPE)

		httpd.serve_forever()

if __name__ == '__main__':
	ProxyKnocker()