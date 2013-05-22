import base64
import hashlib
from datetime import datetime, timedelta
from threading import Timer

class _token_auth(object):
    def __init__(self, expire_time):
        self._clients = {}
        self._expire_time = expire_time
        self._timer = None
        self._is_running = True
        self._expire_tokens()

    def stop(self):
        if self._timer is not None:
            self._is_running = False
            self._timer.cancel()

    def _expire_tokens(self):
        for client, time in self._clients.items():
            if (datetime.now() - time) >= timedelta(0, self._expire_time*60):
                self._clients.pop(client)
        if self._is_running:
            self._timer = Timer(self._expire_time*60, self._expire_tokens)
            self._timer.start()

    def expire_token(self, token, user_agent_header, client_ip):
        if self._clients.pop((token, user_agent_header, client_ip), False):
            return True
        else:
            return False

    def authorize(self, users, authorization, user_agent, remote_addr):
        username, password = (authorization['username'], authorization['password'])
        password = hashlib.md5(password).hexdigest()
        for user in users:
            if user[0] == username and user[1] == password:
                now = datetime.now()
                token = hashlib.md5(username + password + str(user_agent)
                            + str(remote_addr) + str(now)).hexdigest()
                client = (token, user_agent, remote_addr)
                self._clients[client] = now
                return token

    def validate(self, token, user_agent_header, client_ip):
        return self._clients.has_key((token, user_agent_header, client_ip))


try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

class TokenAuth(object):
    def __init__(self, app=None):
        if app is not None:
            self.app = app
            self.init_app(self.app)
        else:
            self.app = None

    def init_app(self, app):
        app.config.setdefault('TOKENAUTH_EXPIRE', 30)
        # Use the newstyle teardown_appcontext if it's available,
        # otherwise fall back to the request context
        if hasattr(app, 'teardown_appcontext'):
            app.teardown_appcontext(self.teardown)
        else:
            app.teardown_request(self.teardown)

    def teardown(self, exception):
        pass
    #    ctx = stack.top
    #    if hasattr(ctx, 'tokenauth'):
    #        ctx.tokenauth.__exit__()

    @property
    def tokenauth(self):
        ctx = stack.top
        if ctx is not None:
            if not hasattr(ctx, 'tokenauth'):
                ctx.tokenauth = _token_auth(self.app.config['TOKENAUTH_EXPIRE'])
            return ctx.tokenauth
