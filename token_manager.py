import base64
import hashlib
from datetime import datetime, timedelta
from threading import Timer

class TokenManager(object):
    def __init__(self, expire_time=None):
        self._clients = {}
        self._timer = None
        self._is_running = True
        if expire_time:
            self._expire_time = expire_time
            self._expire_tokens()

    def __del__(self):
        self.stop()

    def _expire_tokens(self):
        for key, value in self._clients.items():
            time = value['time']
            if (datetime.now() - time) >= timedelta(0, self._expire_time*60):
                self._clients.pop(key)
        if self._is_running:
            self._timer = Timer(self._expire_time*60, self._expire_tokens)
            self._timer.start()

    def stop(self):
        if self._timer is not None:
            self._is_running = False
            self._timer.cancel()

    def expire_token(self, token, user_agent, remote_addr):
        if self._clients.pop((token, user_agent_header, remote_addr), False):
            return True
        else:
            return False

    def get_token(self, user, user_agent, remote_addr):
        now = datetime.now()
        token = hashlib.md5(str(now)).hexdigest()
        client = {'agent': user_agent,
                  'addr': remote_addr,
                  'time': now,
                  'user': user}
        self._clients[token] = client
        return token

    def get_client(self, token):
        if self._clients.has_key(token):
            self._clients[token]['time'] = datetime.now()
            return self._clients[token]
        else:
            return False

    def validate(self, token, user_agent, remote_addr):
        return self._clients.has_key((token, user_agent_header, remote_addr))
