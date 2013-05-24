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
        for key, value in self._clients.items():
            time = value['time']
            if (datetime.now() - time) >= timedelta(0, self._expire_time*60):
                self._clients.pop(key)
        if self._is_running:
            self._timer = Timer(self._expire_time*60, self._expire_tokens)
            self._timer.start()

    def expire_token(self, token, user_agent, remote_addr):
        if self._clients.pop((token, user_agent_header, remote_addr), False):
            return True
        else:
            return False

    def get_token(self, username, password, user_agent, remote_addr):
        now = datetime.now()
        token = unicode(hashlib.md5(username + password + str(user_agent)
                    + str(remote_addr) + str(now)).hexdigest())
        client = {'agent': str(user_agent), 'addr': remote_addr, 'time': now}
        self._clients[token] = client
        return token

    def validate(self, token, user_agent, remote_addr):
        return self._clients.has_key((token, user_agent_header, remote_addr))


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
        ctx = stack.top
        if hasattr(ctx, 'tokenauth'):
            ctx.tokenauth.stop()

    @property
    def tokenauth(self):
        ctx = stack.top
        if ctx is not None:
            if not hasattr(ctx, 'tokenauth'):
                ctx.tokenauth = _token_auth(self.app.config['TOKENAUTH_EXPIRE'])
                print 'oi'
            return ctx.tokenauth
