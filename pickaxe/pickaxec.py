from pickaxe import Message, SelectLoopStateMachine, SimpleTCPClientComponent
import re

class PickaxeC(SelectLoopStateMachine):
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
				print "no conn"
				yield
			print "Connected"
			while any(c.is_connected for c in self.components):
				print "conn"
				yield
			print "Connection lost"

if __name__ == '__main__':
	daemon = PickaxeC("test", "test@123")
	daemon.mainloop()
