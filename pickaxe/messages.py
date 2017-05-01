from abc import ABCMeta, abstractproperty
import inspect, struct

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

	## HEADER and BODY are lists of struct.pack/unpack format, name, and mode.
	##  mode is OR of  1 = "include in message", 2 = "include in authentication"
	##  '' for format is only allowed in BODY and special case meaning
	##  "bytestring for the remainder of the message", MUST be last item

	HEADER = (
		('B', 'T', 3),
	)

	BODY = ()

	def __init__(self, T=None, *args, **kwargs):
		self.meta = {}
		self.T = T if T is not None else self.TYPE

		for name,val in kwargs.items():
			if name in [n for (f,n,m) in self.HEADER + self.BODY]:
				setattr(self, name, val)

	@classmethod
	def _construct_format(cls, data_length=None, _obj=None, include_mode=1):
		
		selected = []

		selected.extend( (f,n) for (f,n,m) in cls.HEADER if (include_mode & m) )

		selected.extend( (f,n) for (f,n,m) in cls.BODY if (include_mode & m) )

		fmt_list, fields = map(list, zip(*selected))  ## zip(*...) is the inverse of zip(...), kind of

		number_of_bytestrings = len([f for f in fmt_list if f == ''])
		if number_of_bytestrings > 1:
			raise Exception("Internal error: Too many variable size bytestrings in BODY")
		if number_of_bytestrings == 1 and not fmt_list[-1] == '':
			raise Exception("Internal error: Variable size bytestring in BODY must be last")

		if fmt_list[-1] == '':
			if data_length:
				fmt_list[-1] = "%is" % (data_length - struct.calcsize("!" + "".join(fmt_list)))
			elif _obj:
				payload = getattr(_obj, fields[-1], None)
				if payload is not None:
					fmt_list[-1] = "%is" % len(payload)

			if fmt_list[-1] == '':
				raise Exception("Internal error: Could not determine variable size bytestring field length")

		return "!" + "".join(fmt_list), fields

	@classmethod
	def parse(cls, data, include_mode=1):
		if inspect.isabstract(cls):  ## Dispatch to child class based on first byte of data
			for cls_ in all_subclasses(cls):
				if not inspect.isabstract(cls_) and cls_.TYPE == ord(data[0]):
					return cls_.parse(data, include_mode=include_mode)

		fmt, fields = cls._construct_format(include_mode=include_mode, data_length = len(data))

		result = cls()

		items = struct.unpack(fmt, data)
		for item, field in zip(items, fields):
			setattr(result, field, item)

		if result.T != cls.TYPE:
			raise Exception("Internal error: T after parsing is not TYPE")

		return result

	def render(self, include_mode=1):
		fmt, fields = self._construct_format(include_mode=include_mode, _obj=self)

		items = [getattr(self, field) for field in fields]

 		return struct.pack(fmt, *items)

class LoginMessage(Message):
	TYPE=0
	BODY = (
		('16s', 'LID', 3),
		('2s', 'V', 3),
		('', 'UID', 3)
	)

class LoginResponseMessage(Message):
	TYPE=1
	BODY = (
		('16s', 'LID', 3),
		('2s', 'V', 3),
		('4s', 'SID', 3),
		('', 'nonce', 3)
	)

def _truncated_get(obj, name):
	val = getattr(obj, name, None)
	if val is None:
		return val
	else:
		return val & 0xFFFF

def _truncated_set(obj, name, val):
	if getattr(obj, name, None) is not None:
		raise AttributeError("Can't set %s_ if %s is already set" % (name, name))
	if val is None:
		raise TypeError("Can't set %s_ to None" % name)
	setattr(obj, name, val)

def untruncate(val, val_):
	result = (val & ~0xFFFFL) | val_
	diff = result - val
	if diff >= 0x8000:
		result -= 0x10000
	elif diff <= -0x8000:
		result += 0x10000
	return result

class SessionMessageBase(Message):
	HEADER = Message.HEADER + (
		('4s', 'SID', 3),
		('Q', 'C', 2),    # Long versions of A and C are authenticated
		('Q', 'A', 2),
		('H', 'C_', 1),   # Short versions and MAC are part of message, but not of MAC calculation
		('H', 'A_', 1),
		('8s', 'M', 1)
	)

	def __init__(self, T=None, SID=None, C=None, A=None, M=None, *args, **kwargs):
		super(SessionMessageBase, self).__init__(T, *args, **kwargs)
		self.SID = SID
		self.C = C
		self.A = A
		self.M = M

	@property
	def C_(self):      return _truncated_get(self, 'C')

	@C_.setter
	def C_(self, val): return _truncated_set(self, 'C', val)

	@property
	def A_(self):      return _truncated_get(self, 'A')

	@A_.setter
	def A_(self, val): return _truncated_set(self, 'A', val)

	def guess_sequence(self, expected_C, expected_A):
		C_ = getattr(self, "C_", None)
		if C_ is None:  # No outgoing C set yet
			self.C = expected_C
		elif getattr(self, "C", None) is None:
			self.C = untruncate(expected_C, C_)

		A_ = getattr(self, "A_", None)
		if A_ is None:  ## Major error: A/A_ not set yet, MUST NOT happen
			raise AssertionError("The value of A_ MUST NOT be guessed")
		elif getattr(self, "A", None) is None:
			self.A = untruncate(expected_A, A_)

class ConnectMessage(SessionMessageBase):
	TYPE=2
	BODY = (
		('16s', 'PID', 3),
		('B', 'Proto', 3),
		('H', 'Port', 3),
		('', 'Target', 3),
	)

class ConnectResponseMessage(SessionMessageBase):
	TYPE=3
	BODY = (
		('16s', 'PID', 3),
		('4s', 'CID', 3),
		('B', 'Status', 3),
	)

class DisconnectMessage(SessionMessageBase):
	pass

class CloseConnMessage(SessionMessageBase):
	BODY = (
		('4s', 'CID', 3),
		('B', 'Status', 3),
	)

class CloseConnClientMessage(CloseConnMessage):
	TYPE=8

class CloseConnServerMessage(CloseConnMessage):
	TYPE=9

class DataMessage(SessionMessageBase):
	BODY = (
		('4s', 'CID', 3),
		('', 'Data', 3),
	)

class DataClientMessage(DataMessage):
	TYPE=10

class DataServerMessage(DataMessage):
	TYPE=11

class EchoMessage(SessionMessageBase):
	BODY = (
		('', 'Data', 3),
	)

class EchoClientMessage(EchoMessage):
	TYPE=12

class EchoServerMessage(EchoMessage):
	TYPE=13

class DisconnectClientMessage(DisconnectMessage):
	TYPE=126

class DisconnectServerMessage(DisconnectMessage):
	TYPE=127
