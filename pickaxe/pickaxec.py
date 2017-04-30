from pickaxe import V, SelectLoopStateMachine, MessageHandlingLoop, SimpleTCPClientComponent, AuthenticationState
from pickaxe.messages import *
import uuid

class PickaxeC(MessageHandlingLoop, SelectLoopStateMachine):
	def __init__(self, username, password, host="localhost", port=8865):
		super(PickaxeC, self).__init__()

		self.host = host
		self.port = port
		self.username = username
		self.password = password
		self.auth = None
		self.lid = None

		self.components.append( SimpleTCPClientComponent(host=self.host, port=self.port) )

	def state_machine(self):
		while True:
			# No connection
			while not any(c.is_connected for c in self.components):
				yield

			self.lid = uuid.uuid4()
			login = LoginMessage(LID=self.lid.bytes, V=V, UID=self.username)
			for c in self.components:
				if c.is_connected:
					c.connections[0].send_message(login)
			
			yield
			
			while any(c.is_connected for c in self.components):
				print "conn"
				yield
			print "Connection lost"

	def handle_message(self, message):
		if isinstance(message, LoginResponseMessage):
			assert message.LID == self.lid.bytes  ## FIXME Proper check
			self.auth = AuthenticationState(self.lid, message.SID, self.username, self.password, message.nonce)
			u = uuid.uuid4()
			print "Sending Ping", u
			ping = EchoClientMessage(Data=u.bytes)
			ping.SID = message.SID
			ping.A = 0
			self.auth.generate_mac(ping)
			message.meta["connection"].send_message(ping)
		else:
			print "Unhandled message", message


if __name__ == '__main__':
	daemon = PickaxeC("test", "test@123")
	daemon.mainloop()
