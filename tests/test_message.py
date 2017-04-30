from pickaxe import *
import pytest

@pytest.fixture
def message_login():
	return LoginMessage(LID=16*b'\x00', V='\x00\x00', UID=b'test')

def test_creation(message_login):
	assert message_login

def test_render(message_login):
	data = message_login.render()
	assert len(data) == 1+16+2+len(message_login.UID)

def test_parse(message_login):
	data = message_login.render()
	m = Message.parse(data)

	assert type(m) == LoginMessage
	assert m.UID == message_login.UID


@pytest.fixture
def message_data_short():
	return DataClientMessage(SID=4*b'\x00', C=2, A=1, CID=b'\x12\x23\x34\x45', Data=b'Hello, World.')

@pytest.fixture
def authentication_state():
	return AuthenticationState(16*b'\x00', 4*b'\x00', username="test", password="test@123", nonce=16*b'\x00', kdf_count=23)

def test_authentication(authentication_state, message_data_short):
	authentication_state.generate_mac(message_data_short)
	
	assert authentication_state.verify_mac(message_data_short)

	message_data_short.M = 8*b'\x00'

	assert authentication_state.verify_mac(message_data_short) == False

def test_authenticated_ping(authentication_state):
	message = EchoClientMessage(SID=b'1234', A=0, Data=14*b'\x00'+b'az')
	authentication_state.generate_mac(message)

	data = message.render()

	message_ = Message.parse(data)

	authentication_state.verify_mac(message_)
