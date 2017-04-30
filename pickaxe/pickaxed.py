from pickaxe import V, MessageHandlingLoop, SimpleTCPServerComponent, TCPServerComponentBase, TCPConnectionBase, ComponentBase, AuthenticationState
from pickaxe.messages import *
import re, time, os

class UserBase(object):
	def __init__(self):
		self.users = {}
		self.lockout_times = {}

	def add_users(self, users):
		for u,p in users:
			self.users[u.lower()] = (p, )

	def throttled_get_user(self, user):
		user = user.lower()
		now = time.time()
		lt = self.lockout_times.get(user, None)
		if lt is not None:
			if now >= lt[0] and now <= lt[1]:
				return None
		user_data = self.users.get(user, None)
		if user_data:
			self.lockout_times[user] = (now, now + 3)  ## FIXME Configurable
			return user_data
		return None

class Session(AuthenticationState):
	def __init__(self, *args, **kwargs):
		self.pending = True
		self.parent = kwargs.pop("parent", None)

		super(Session, self).__init__(*args, **kwargs)

		if self.parent:
			self.timer = self.parent.add_timer(60, self.timeout) ## FIXME Configurable timeout

	def timeout(self):
		print "Login %s timed out" % self.SID
		self.parent.remove_session(self.SID)
		self.timer = None

	def verify_mac(self, *args, **kwargs):
		if self.timer:
			self.parent.del_timer(self.timer)
			self.timer = None
		result = super(Session, self).verify_mac(*args, **kwargs)

		if self.pending:
			if not result:
				print "Login %s invalid" % self.SID
				self.parent.remove_session(self.SID)
			self.pending = False
			print "Login by %s" % self.username

		return result


class DaemonManager(ComponentBase):
	def __init__(self, parent, users):
		super(DaemonManager, self).__init__()
		self.parent = parent
		self.users = users
		self.sessions = {}

	def process_data(self, r,w,x): pass

	def handle_message(self, message):
		if isinstance(message, LoginMessage):
			self.process_login(message)
		else:
			if self.authenticate_message(message):
				self.process_message(message)
			else:
				## Messages out of session and invalid messages are ignored
				print "Unauthenticated message", message

	def process_login(self, message):
		## FIXME Check V
		## FIXME Simply resend for duplicate LID
		user = self.users.throttled_get_user(message.UID)
		if user:
			SID = os.urandom(4)  ## FIXME Check for duplicate
			nonce = os.urandom(16)
			now = time.time()
			self.sessions[SID] = Session(message.LID, SID, message.UID, user[0], nonce, parent=self)

			self.parent.dispatch_message(  LoginResponseMessage(LID=message.LID, V=V, SID=SID, nonce=nonce), message  )
		## FIXME Prevent user enumeration

	def authenticate_message(self, message):
		session = self.sessions.get(message.SID, None)
		if session is not None:
			return session.verify_mac(message)
		return False

	def process_message(self, message):
		pass

	def remove_session(self, SID):
		self.sessions.pop(SID, None)

	
class PickaxeD(MessageHandlingLoop):
	def __init__(self, users):
		super(PickaxeD, self).__init__()

		http = SimpleHTTPServerComponent(port=4567)
		tcp = SimpleTCPServerComponent()
		self.manager = DaemonManager(self, users)

		http.start_listen()
		tcp.start_listen()

		self.components.extend([http, tcp, self.manager])

	def handle_message(self, message):
		if message.T & 1 == 0:
			self.manager.handle_message(message)
		else:
			print "Invalid message type 0x%02X received" % message.T

	def dispatch_message(self, message, query=None):
		query.meta["connection"].send_message(message)  ## FIXME Proper response routing


class HTTPRequest(object):
	HTTP_REQUEST_RE = re.compile(r'^(?P<verb>[a-z]+?)[ \t]+(?P<path>.+?)(?:[ \t]+HTTP[ \t]*\/[ \t]*(?P<version>\d+\.\d+))?[ \t]*(?P<CRLF>[\r])?[\n]' +
		r'(?P<headers>(?:[^\r\n]+(?(CRLF)[\r]|)[\n])*)' +
		r'(?(CRLF)[\r]|)[\n]', re.I)

	def __init__(self, method, path, version=None):
		self.method = method
		self.path = path
		self.version = version if version else b'0.9'

	@classmethod
	def parse_one(cls, data):
		m = cls.HTTP_REQUEST_RE.match(data)
		if not m: return None, data

		## FIXME Handle body
		request = cls(m.group('verb').upper(), m.group('path'), m.group('version'))

		return request, data[m.end(0):]

class HTTPResponse(object):
	STATUS_CODES = {200: b'OK'}

	def __init__(self, status_code, status_text=None, body=None, version=b"1.1", headers={}):
		self.status_code = status_code
		self.status_text = status_text if status_text is not None else self.STATUS_CODES.get(status_code, b"Unknown status")
		self.body = body
		self.version = version
		self.headers = headers
		if not b"Content-Length".upper() in [h.upper() for h in headers.keys()]:
			if self.body:
				self.headers[b"Content-Length"] = b"%i" % len(self.body)

	def render(self):
		return b"HTTP/%s %i %s\r\n%s\r\n" % (
			self.version, self.status_code, self.status_text,
			b"\r\n".join( b"%s: %s" % (k,v) for (k,v) in self.headers.items() ) + (b"\r\n" if len(self.headers) else b"")
		) + (self.body if self.body else b"")


class SimpleHTTPServerConnection(TCPConnectionBase):
	def __init__(self, parent, conn, address):
		super(SimpleHTTPServerConnection, self).__init__(parent, conn, address)
		self.close_after_sending = False

	def process_data(self, do_read, do_write, do_special):
		super(SimpleHTTPServerConnection, self).process_data(do_read, do_write, do_special)

		if (self.close_after_sending or not self.open_for_read) and not len(self.outbuf):
			## No remaining data to be sent. Close
			self.disconnect()

	def parse_and_handle(self):
		while len(self.inbuf):
			request, self.inbuf = HTTPRequest.parse_one(self.inbuf)
			if not request: return
			self.handle_request(request)

	def handle_request(self, request):
		response = HTTPResponse(200, body="Your request has been ignored, thank you", headers={"Connection": "close"})

		self.send_response(response, close_after_sending=True)

	def send_response(self, response, close_after_sending=False):
		self.outbuf = self.outbuf + response.render()
		self.close_after_sending = close_after_sending or self.close_after_sending

class SimpleHTTPServerComponent(TCPServerComponentBase):
	CONNECTION_CLASS = SimpleHTTPServerConnection

	def __init__(self, host='0.0.0.0', port=80, *args, **kwargs):
		super(SimpleHTTPServerComponent, self).__init__(host, port, *args, **kwargs)


if __name__ == '__main__':
	users = UserBase()
	users.add_users({'test': 'test@123'}.items())
	daemon = PickaxeD(users)
	daemon.mainloop()
