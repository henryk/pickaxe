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

	## HEADER and BODY are lists of struct.pack/unpack format and name.
	##  '' for format is only allowed in BODY and special case meaning
	##  "bytestring for the remainder of the message", MUST be last item

	HEADER = (
		('B', 'T'),
	)

	BODY = ()

	def __init__(self, T=None):
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
