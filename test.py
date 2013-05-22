#!/usr/bin/env python

from http_token_auth import HTTPTokenAuth
from time import sleep
import base64
import hashlib

with HTTPTokenAuth(0.1) as a:
	users = {'system':'%s' % hashlib.md5('system').hexdigest(), 'system2':'%s' % hashlib.md5('system').hexdigest()}
	auth_header = base64.b64encode('system:system')
	auth_header2 = base64.b64encode('system2:system')
	agent_header = 'teste'
	ip = '127.0.0.1'
	token = a.authorize(users, auth_header, agent_header, ip)
	sleep(1)
	token2 = a.authorize(users, auth_header2, agent_header, ip)
	sleep(4)
	a.expire_token(token2, agent_header, ip)
	print a.validate(token, agent_header, ip)
	print a.validate(token2, agent_header, ip)