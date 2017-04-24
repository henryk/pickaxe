from abc import ABCMeta, abstractmethod
from pickaxe import Message
import select, socket, re


class SelectLoop(object):
	def __init__(self):
		self.exit = False
		self.components = []

	def loop_once(self, timeout=None):
			read_candidate, write_candidate, special_candidate = dict(), dict(), dict()

			for component in self.components:
				r,w,x, timeout_ = component.get_select()

				for r_ in r:
					read_candidate.setdefault(r_, set()).add(component)

				for w_ in w:
					write_candidate.setdefault(w_, set()).add(component)

				for x_ in x:
					special_candidate.setdefault(x_, set()).add(component)

				if timeout is None:
					timeout = timeout_
				elif timeout_ is not None:
					timeout = min(timeout, timeout_)

			to_read, to_write, to_special = select.select(read_candidate.keys(), write_candidate.keys(), special_candidate.keys(), timeout)

			for component in self.components:
				r = [r_ for r_ in to_read if component in read_candidate[r_] ]
				w = [w_ for w_ in to_write if component in write_candidate[w_] ]
				x = [x_ for x_ in to_special if component in special_candidate[x_] ]

				r,w,x = select.select(r,w,x,0)

				component.process_data(r, w, x)

	def mainloop(self):
		while not self.exit:
			self.loop_once()

class PickaxeD(SelectLoop):
	pass

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


class TCPConnectionBase(object):
	__metaclass__ = ABCMeta

	def __init__(self, parent, conn, address):
		self.parent = parent
		self.conn = conn
		self.address = address
		self.inbuf = b''
		self.outbuf = b''
		conn.setblocking(0)
		self.open_for_read = True

	def fileno(self):
		return self.conn.fileno()

	def need_write(self):
		return len(self.outbuf) > 0

	def need_read(self):
		return self.open_for_read

	def process_data(self, do_read, do_write, do_special):
		if do_read:
			chunk = self.conn.recv(16384)
			if not len(chunk):
				self.open_for_read = False

			self.inbuf = self.inbuf + chunk

		self.parse_and_handle()

		if len(self.outbuf) and do_write:
			sent = self.conn.send(self.outbuf)
			self.outbuf = self.outbuf[sent:]

		if len(self.inbuf) and not self.open_for_read:
			## Invalid partial garbage received that can't be handled. Close
			self.disconnect()

	def disconnect(self):
		self.parent.notify_disconnected(self)
		self.conn.close()

	@abstractmethod
	def parse_and_handle(self):
		pass


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

class SimpleTCPServerConnection(TCPConnectionBase):
	def parse_and_handle(self):
		while len(self.inbuf):
			if len(self.inbuf) >= 4:
				(length, ) = struct.unpack("<I", self.inbuf[:4])
				if inbuf >= 4 + length:
					data, self.inbuf = self.inbuf[4:4+length], self.inbuf[4+length:]
					message = Message.parse(data)

					self.parent.handle_message(self, message)
	

class TCPComponentBase(object):
	CONNECTION_CLASS = None

	def __init__(self, host='0.0.0.0', port=None):
		self.host = host
		self.port = port
		self.connections = []
		self.listen_socket = None
		self.clients = []
		self.incoming_messages = []

	def start_listen(self):
		if self.listen_socket:
			self.stop_listen(self)

		self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.listen_socket.bind( (self.host, self.port) )
		self.listen_socket.listen(2)
		self.listen_socket.setblocking(0)

	def stop_listen(self):
		if self.listen_socket:
			self.listen_socket.close()
			self.listen_socket = None

	def get_select(self):
		r,w,x, timeout = [c for c in self.clients if c.need_read()],[c for c in self.clients if c.need_write()],[], None

		if self.listen_socket:
			r.append(self.listen_socket)

		return r,w,x, timeout

	def process_data(self, r, w, x):
		if self.listen_socket and self.listen_socket in r:
			self.accept_client()

		for client in set(r).union(set(w)):
			if isinstance(client, self.CONNECTION_CLASS):
				client.process_data(client in r, client in w, client in x)

	def accept_client(self):
		if not self.listen_socket: return

		(conn, address) = self.listen_socket.accept()
		self.clients.append( self.CONNECTION_CLASS(self, conn, address) )

	def handle_message(self, client, message):
		message.meta["component"] =  self
		message.meta["client"] = client

		self.incoming_messages.append(message)


	def notify_disconnected(self, client):
		if client in self.clients:
			self.clients.remove(client)

class SimpleHTTPServerComponent(TCPComponentBase):
	CONNECTION_CLASS = SimpleHTTPServerConnection

	def __init__(self, host='0.0.0.0', port=80, *args, **kwargs):
		super(SimpleHTTPServerComponent, self).__init__(host, port, *args, **kwargs)

class SimpleTCPServerComponent(TCPComponentBase):
	CONNECTION_CLASS = SimpleTCPServerConnection

	def __init__(self, host='0.0.0.0', port=8865, *args, **kwargs):
		super(SimpleTCPServerComponent, self).__init__(host, port, *args, **kwargs)


if __name__ == '__main__':
	daemon = PickaxeD()
	http = SimpleHTTPServerComponent(port=4567)
	tcp = SimpleTCPServerComponent()

	http.start_listen()
	tcp.start_listen()

	daemon.components.extend([http, tcp])

	daemon.mainloop()
