from pickaxe import Message, SelectLoop, SimpleTCPClientComponent
import re

class PickaxeC(SelectLoop):
	pass

if __name__ == '__main__':
	daemon = PickaxeC()
	tcp = SimpleTCPClientComponent(host="localhost")

	daemon.components.extend([tcp])

	daemon.mainloop()
