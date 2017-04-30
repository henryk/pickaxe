from pickaxe import V, SelectLoopStateMachine, MessageHandlingLoop, SimpleTCPClientComponent
from pickaxe.messages import *
import uuid

class PickaxeC(MessageHandlingLoop, SelectLoopStateMachine):
	def __init__(self, username, password, host="localhost", port=8865):
		super(PickaxeC, self).__init__()

		self.host = host
		self.port = port
		self.username = username
		self.password = password

		self.components.append( SimpleTCPClientComponent(host=self.host, port=self.port) )

	def state_machine(self):
		while True:
			# No connection
			while not any(c.is_connected for c in self.components):
				yield

			lid = uuid.uuid4()
			login = LoginMessage(LID=lid.bytes, V=V, UID=self.username)
			for c in self.components:
				if c.is_connected:
					c.connections[0].send_message(login)
			
			yield
			
			while any(c.is_connected for c in self.components):
				print "conn"
				yield
			print "Connection lost"

	def handle_message(self, message):
		print message


if __name__ == '__main__':
	daemon = PickaxeC("test", "test@123")
	daemon.mainloop()
