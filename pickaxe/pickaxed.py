from pickaxe import V, MessageHandlingLoop, SimpleTCPServerComponent, TCPServerComponentBase, TCPConnectionBase, ComponentBase
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

class DaemonManager(ComponentBase):
	def __init__(self, parent, users):
		super(DaemonManager, self).__init__()
		self.parent = parent
		self.users = users
		self.pending_sessions = {}
		self.sessions = {}

	def process_data(self, r,w,x): pass

	def handle_message(self, message):
		response = None
		if isinstance(message, LoginMessage):
			## FIXME Check V
			## FIXME Simply resend for duplicate LID
			user = self.users.throttled_get_user(message.UID)
			if user:
				SID = os.urandom(4)  ## FIXME Check for duplicate
				nonce = os.urandom(16)
				now = time.time()
				t = self.add_timer(60, lambda : self.pending_sessions.pop(SID, None)) ## FIXME Configurable timeout
				self.pending_sessions[SID] = (message.LID, nonce, t, user) 

				response = LoginResponseMessage(LID=message.LID, V=V, SID=SID, nonce=nonce)
				## FIXME Prevent user enumeration
		else:
			print "Unhandled message", message

		if response is not None:
			self.parent.dispatch_message(response, message)
	
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
