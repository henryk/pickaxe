from abc import ABCMeta, abstractproperty, abstractmethod
import inspect, struct, select, socket

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

class SimpleTCPServerConnection(TCPConnectionBase):
	def parse_and_handle(self):
		while len(self.inbuf):
			if len(self.inbuf) >= 4:
				(length, ) = struct.unpack("<I", self.inbuf[:4])
				if inbuf >= 4 + length:
					data, self.inbuf = self.inbuf[4:4+length], self.inbuf[4+length:]
					message = Message.parse(data)

					self.parent.handle_message(self, message)


class SimpleTCPServerComponent(TCPComponentBase):
	CONNECTION_CLASS = SimpleTCPServerConnection

	def __init__(self, host='0.0.0.0', port=8865, *args, **kwargs):
		super(SimpleTCPServerComponent, self).__init__(host, port, *args, **kwargs)

