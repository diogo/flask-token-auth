import base64
import md5
from datetime import datetime, timedelta
from threading import Timer

class HTTPTokenAuth(object):
	def __init__(self, user_table_model, expire_time):
		self._clients = {}
		self._users = user_table_model
		self.expire_time = expire_time
		self._api = restful_api
		self._expire_tokens()

	def _expire_tokens(self):
		for client, time in self._clients.items():
			if ((datetime.now() - time ) <= timedelta(0, self._expire_time*60)):
				self._clients.pop(client)
		Timer(self._expire_time*60, self._expire_tokens).start()

	def expire_token(self, token, user_agent_header, client_ip):
		if self._clients.pop((token, user_agent_header, client_ip), False):
			return True
		else:
			return False

	def authorize(authorization_header, user_agent_header, client_ip):
        username, password = base64.b64decode(authorization_header).split(':')
        password = md5.new(password).digest()
        user = self._users.query.filter(self._users.username == username,
							self._users.password == password).first()
		if user is not None:
			token = md5.new(username + password + user_agent_header
						+ client_ip).digest()
			client = (token, user_agent_header, client_ip)
			self._clients[client] = datetime.now()

	def validate(token, user_agent_header, client_ip):
		return self._clients.has_key((token, user_agent_header, client_ip))
