from pickaxe.messages import *

import struct, select, socket, time, thread, os, sys, hmac, hashlib
from abc import ABCMeta, abstractproperty, abstractmethod

VERSION = (1, 0)
V = struct.pack('BB', *VERSION)

def kdf(lid, sid, username, password, nonce, kdf_count):
	salt = bytes(lid) + bytes(sid) + bytes(nonce) + bytes(username)
	return hashlib.pbkdf2_hmac('sha256', bytes(password), salt, kdf_count)

class AuthenticationState(object):
	def __init__(self, lid, sid, username, password, nonce, kdf_count=123456):
		self.lid = None
		self.sid = None
		self.our_seq = 0L
		self.their_seq = 0L

		self.key = kdf(self.lid, self.sid, username, password, nonce, kdf_count)

	def generate_mac(self, message):
		message.set_counters(self.our_seq + 1, self.their_seq)

		message.M = self.calculate_mac(message)

		self.our_seq = message.C

	def verify_mac(self, message):
		message.set_counters(self.their_seq, self.our_seq)

		M_ = self.calculate_mac(message)

		if M_ == message.M:
			self.their_seq = message.C
			return True
		else:
			return False

	def calculate_mac(self, message):
		data = message.render(include_mode=2)
		h = hmac.new(self.key, data, digestmod=hashlib.sha256)
		return h.digest()[:8]


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

class SelectLoopStateMachine(SelectLoop):
	__metaclass__ = ABCMeta

	@abstractmethod
	def state_machine(self):
		yield

	def __init__(self, *args, **kwargs):
		super(SelectLoopStateMachine, self).__init__(*args, **kwargs)
		self.state = self.state_machine()

	def loop_once(self, timeout=None):
		super(SelectLoopStateMachine, self).loop_once(timeout)
		if self.state:
			try:
				self.state.next()
			except StopIteration:
				self.exit = True

class MessageHandlingLoop(SelectLoop):
	__metaclass__ = ABCMeta

	@abstractmethod
	def handle_message(self, message):
		pass

	def loop_once(self, *args, **kwargs):
		super(MessageHandlingLoop, self).loop_once(*args, **kwargs)
		for c in self.components:
			for m in c.incoming_messages:
				self.handle_message(m)


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

	def notify_disconnected(self, connection):
		super(TCPClientComponentBase, self).notify_disconnected(connection)
		self.outgoing_socket = None

	@property
	def is_connected(self):
		return len(self.connections) > 0


class SimpleTCPConnection(TCPConnectionBase):
	def process_data(self, do_read, do_write, do_special):
		super(SimpleTCPConnection, self).process_data(do_read, do_write, do_special)

		if not self.open_for_read and not len(self.outbuf):
			## No remaining data to be sent and not open for reading -> Close
			## The plain TCP protocol will never partially close a connection. If it's
			## closed for reading that means that the server closed the connection
			self.disconnect()

	def parse_and_handle(self):
		while len(self.inbuf):
			if len(self.inbuf) >= 4:
				(length, ) = struct.unpack("!I", self.inbuf[:4])
				if len(self.inbuf) >= 4 + length:
					data, self.inbuf = self.inbuf[4:4+length], self.inbuf[4+length:]
					message = Message.parse(data)

					self.parent.handle_message(self, message)
				else:
					break
			else:
				break

	def send_message(self, message):
		m = message.render()
		self.outbuf += struct.pack("!I", len(m)) + m


class SimpleTCPServerComponent(TCPServerComponentBase):
	CONNECTION_CLASS = SimpleTCPConnection

	def __init__(self, host='0.0.0.0', port=8865, *args, **kwargs):
		super(SimpleTCPServerComponent, self).__init__(host, port, *args, **kwargs)


class SimpleTCPClientComponent(TCPClientComponentBase):
	CONNECTION_CLASS = SimpleTCPConnection

	def __init__(self, host, port=8865, *args, **kwargs):
		super(SimpleTCPClientComponent, self).__init__(host, port, *args, **kwargs)
