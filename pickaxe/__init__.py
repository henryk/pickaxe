from abc import ABCMeta, abstractproperty, abstractmethod
import inspect, struct, select, socket, time, thread, os, sys

def all_subclasses(cls_a):
	for cls_b in cls_a.__subclasses__():
		yield cls_b
		for cls_c in all_subclasses(cls_b):
			yield cls_c

class Message(object):
	__metaclass__ = ABCMeta

	@abstractproperty
	@classmethod
	def TYPE(self): return None

	## HEADER and BODY are lists of struct.pack/unpack format and name.
	##  '' for format is only allowed in BODY and special case meaning
	##  "bytestring for the remainder of the message", MUST be last item

	HEADER = (
		('B', 'T'),
	)

	BODY = ()

	def __init__(self, T=None):
		self.meta = {}
		self.T = T if T is not None else self.TYPE

	@classmethod
	def _construct_format(cls, header=True, body=True, omit_fields=(), data_length=None, _obj=None):
		
		selected = []

		if header:
			selected.extend( (f,n) for (f,n) in cls.HEADER if n not in omit_fields )

		if body:
			selected.extend( (f,n) for (f,n) in cls.BODY if n not in omit_fields )

		fmt_list, fields = zip(*selected)  ## zip(*...) is the inverse of zip(...), kind of

		number_of_bytestrings = len([f for f in fmt_list if f == ''])
		if number_of_bytestrings > 1:
			raise Exception("Internal error: Too many variable size bytestrings in BODY")
		if number_of_bytestrings == 1 and not fmt_list[-1] == '':
			raise Exception("Internal error: Variable size bytestring in BODY must be last")

		if fmt_list[-1] == '':
			if data_length:
				fmt_list[-1] = "%is" % (data_length - struct.calcsize("".join(fmt_list)))
			elif _obj:
				payload = getattr(_obj, fields[-1], None)
				if payload is not None:
					fmt_list[-1] = "%is" % len(payload)

			if fmt_list[-1] == '':
				raise Exception("Internal error: Could not determine variable size bytestring field length")

		return "".join(fmt_list), fields

	@classmethod
	def parse(cls, data, parse_header=True, parse_body=True, omit_fields=()):
		if inspect.isabstract(cls):  ## Dispatch to child class based on first byte of data
			for cls_ in all_subclasses(cls):
				if not inspect.isabstract(cls_) and cls_.TYPE == ord(data[0]):
					return cls_.parse(data, parse_header, parse_body, omit_fields)

		fmt, fields = cls._construct_format(parse_header, parse_body, omit_fields, data_length = len(data))

		result = cls()

		items = struct.unpack(fmt, data)
		for item, field in zip(items, fields):
			setattr(result, field, item)

		if result.T != cls.TYPE:
			raise Exception("Internal error: T after parsing is not TYPE")

		return result

	def render(self, render_header=True, render_body=True, omit_fields=()):
		fmt, fields = self._construct_format(render_header, render_body, omit_fields, _obj=self)

		items = [getattr(self, field) for field in fields]

		return struct.pack(fmt, *items)

class LoginMessageBase(Message):
	BODY = (
		('16s', 'LID'),
		('2s', 'V'),
		('', 'UID')
	)

class LoginMessage(LoginMessageBase):
	TYPE=0

class LoginResponseMessage(LoginMessageBase):
	TYPE=1

class SessionMessageBase(Message):
	HEADER = Message.HEADER + (
		('4s', 'SID'),
		('<H', 'C_'),
		('8s', 'M')
	)

	def __init__(self, T=None, SID=None, C=None, M=None):
		super(SessionMessage, self).__init__(T)
		self.SID = SID
		self.C = C
		self.M = M

	@property
	def C_(self):
		C = getattr(self, 'C', None)
		if C is None:
			return C
		else:
			return C & 0xFFFF

	@C_.setter
	def C_(self, val):
		if getattr(self, 'C', None) is not None:
			raise AttributeError("Can't set C_ if C is already set")
		if val is None:
			raise TypeError("Can't set C_ to None")
		self.C = val

class ConnectMessage(SessionMessageBase):
	TYPE=2
	BODY = (
		('16s', 'PID'),
		('B', 'Proto'),
		('<H', 'Port'),
		('', 'Target'),
	)

class ConnectResponseMessage(SessionMessageBase):
	TYPE=3
	BODY = (
		('16s', 'PID'),
		('4s', 'CID'),
		('B', 'Status'),
	)

class DisconnectMessage(SessionMessageBase):
	pass

class CloseConnMessage(SessionMessageBase):
	BODY = (
		('4s', 'CID'),
		('B', 'Status'),
	)

class CloseConnClientMessage(CloseConnMessage):
	TYPE=8

class CloseConnServerMessage(CloseConnMessage):
	TYPE=9

class DataMessage(SessionMessageBase):
	BODY = (
		('4s', 'CID'),
		('', 'Data'),
	)

class DataClientMessage(DataMessage):
	TYPE=10

class DataServerMessage(DataMessage):
	TYPE=11

class DisconnectClientMessage(DisconnectMessage):
	TYPE=126

class DisconnectServerMessage(DisconnectMessage):
	TYPE=127


class SelectLoop(object):
	def __init__(self):
		self.exit = False
		self.components = []

	def loop_once(self, timeout=None):
			read_candidate, write_candidate, special_candidate = dict(), dict(), dict()
			had_timeout = []

			for component in self.components:
				r,w,x, timeout_ = component.get_select()

				for r_ in r:
					read_candidate.setdefault(r_, set()).add(component)

				for w_ in w:
					write_candidate.setdefault(w_, set()).add(component)

				for x_ in x:
					special_candidate.setdefault(x_, set()).add(component)

				if timeout_ is not None:
					had_timeout.append(component)

				if timeout is None:
					timeout = timeout_
				elif timeout_ is not None:
					timeout = min(timeout, timeout_)

			to_read, to_write, to_special = select.select(read_candidate.keys(), write_candidate.keys(), special_candidate.keys(), timeout)

			for component in self.components:
				if component in had_timeout:
					component.process_timeout()

				r = [r_ for r_ in to_read if component in read_candidate[r_] ]
				w = [w_ for w_ in to_write if component in write_candidate[w_] ]
				x = [x_ for x_ in to_special if component in special_candidate[x_] ]

				r,w,x = select.select(r,w,x,0)

				component.process_data(r, w, x)

	def mainloop(self):
		while not self.exit:
			self.loop_once()

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

class ComponentBase(object):
	__metaclass__ = ABCMeta

	def __init__(self):
		self.incoming_messages = []
		self.timers = []

	def get_select(self):
		timeout = None
		if self.timers:
			## FIXME: Handle clock jumps
			now = time.time()
			timeout = max(0, self.timers[0][0] - now)
		return [], [], [], timeout


	@abstractmethod
	def process_data(self, r, w, x): pass

	def process_timeout(self):
		## FIXME: Handle clock jumps
		now = time.time()
		triggered = [t for t in self.timers if now >= t[0]]
		for t in triggered:
			self.timers.remove(t)
			t[-1]()

	def add_timer(self, timeout, callback):
		now = time.time()
		t = [now + timeout, now, timeout, callback]
		self.timers.append(t)
		self.timers.sort()
		return t

	def del_timer(self, t):
		self.timers.remove(t)


class TCPComponentBase(ComponentBase):
	CONNECTION_CLASS = None

	def __init__(self, host='0.0.0.0', port=None):
		super(TCPComponentBase, self).__init__()
		self.host = host
		self.port = port
		self.connections = []

	def get_select(self):
		r,w,x, timeout = super(TCPComponentBase, self).get_select()
		return r + [c for c in self.connections if c.need_read()], w + [c for c in self.connections if c.need_write()], x, timeout

	def process_data(self, r, w, x):
		for connection in set(r).union(set(w)):
			if isinstance(connection, self.CONNECTION_CLASS):
				connection.process_data(connection in r, connection in w, connection in x)

	def handle_message(self, connection, message):
		message.meta["component"] =  self
		message.meta["connection"] = connection

		self.incoming_messages.append(message)


	def notify_disconnected(self, connection):
		if connection in self.connections:
			self.connections.remove(connection)

class TCPServerComponentBase(TCPComponentBase):

	def __init__(self, host='0.0.0.0', port=None):
		super(TCPServerComponentBase, self).__init__(host, port)
		self.listen_socket = None

	def get_select(self):
		r,w,x, timeout = super(TCPServerComponentBase, self).get_select()

		if self.listen_socket:
			r.append(self.listen_socket)

		return r,w,x, timeout

	def process_data(self, r, w, x):
		if self.listen_socket and self.listen_socket in r:
			self.accept_client()

		super(TCPServerComponentBase, self).process_data(r, w, x)

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

	def accept_client(self):
		if not self.listen_socket: return

		(conn, address) = self.listen_socket.accept()
		self.connections.append( self.CONNECTION_CLASS(self, conn, address) )

class TCPClientComponentBase(TCPComponentBase):
	def __init__(self, host, port):
		super(TCPClientComponentBase, self).__init__(host, port)
		self.connecting_pipe = None
		self.pending_socket = None
		self.outgoing_socket = None
		self.backoff = None
		self.connecting_socket_job = None


	def get_select(self):
		if not self.outgoing_socket and not self.connecting_pipe:
			self.schedule_connection()

		r,w,x,t = super(TCPClientComponentBase, self).get_select()

		if self.connecting_pipe:
			r = r + [self.connecting_pipe[0]]

		return r,w,x,t

	def process_data(self, r, w, x):
		if self.connecting_pipe and self.connecting_pipe[0] in r:
			## The do_connect() thread successfully created a connection
			os.read(self.connecting_pipe[0], 1)
			os.close(self.connecting_pipe[0])
			os.close(self.connecting_pipe[1])
			self.connecting_pipe = None
			self.outgoing_socket = self.pending_socket
			self.pending_socket = None

			if self.outgoing_socket:
				address = self.outgoing_socket.getpeername()
				self.connections.append( self.CONNECTION_CLASS(self, self.outgoing_socket, address) )

		super(TCPClientComponentBase, self).process_data(r, w, x)

	def schedule_connection(self):
		if self.connecting_socket_job:
			return

		if self.backoff is None:
			self.backoff = 0
		elif self.backoff == 0:
			self.backoff = 1
		elif self.backoff < 32:
			self.backoff = self.backoff*2

		self.connecting_socket_job = self.add_timer(self.backoff, self.try_connect)

	def try_connect(self):
		self.connecting_socket_job = None

		# We're going to use socket.create_connection() which transparently handles IPv4 and IPv6
		# Unfortunately it's not non-blocking compatible, so we'll spawn a thread to execute that in
		# The thread will signal back to the main thread with a Pipe
		self.connecting_pipe = os.pipe()

		thread.start_new_thread(self.do_connect, ())

	def do_connect(self): ## Executed in new thread
		try:
			sock = socket.create_connection( (self.host, self.port) )
			if sock:
				self.backoff = None
				sock.setblocking(0)
				self.pending_socket = sock
		except Exception as e:
			print >>sys.stderr, e, "while connecting to", (self.host, self.port)
		finally:
			os.write(self.connecting_pipe[1], 'A') ## This will wake the main loop and proceed in self.process_data



class SimpleTCPConnection(TCPConnectionBase):
	def parse_and_handle(self):
		while len(self.inbuf):
			if len(self.inbuf) >= 4:
				(length, ) = struct.unpack("<I", self.inbuf[:4])
				if inbuf >= 4 + length:
					data, self.inbuf = self.inbuf[4:4+length], self.inbuf[4+length:]
					message = Message.parse(data)

					self.parent.handle_message(self, message)


class SimpleTCPServerComponent(TCPServerComponentBase):
	CONNECTION_CLASS = SimpleTCPConnection

	def __init__(self, host='0.0.0.0', port=8865, *args, **kwargs):
		super(SimpleTCPServerComponent, self).__init__(host, port, *args, **kwargs)


class SimpleTCPClientComponent(TCPClientComponentBase):
	CONNECTION_CLASS = SimpleTCPConnection

	def __init__(self, host, port=8865, *args, **kwargs):
		super(SimpleTCPClientComponent, self).__init__(host, port, *args, **kwargs)
