# Pickaxe TCP over anything protocol

## Overview
### Layering, Mobility

The common protocol assumes a method to transfer packets from client to server and vice versa. Both parties may send a packet at any time. The server will accept packets from the client on any of the methods and try to respond with the same method. The client is free to chose any method or multiple methods. Duplicate packets will only be processed once, but reponses will be resent on packet re-reception (within reason).

    ------------------------- Control and data --------------------------
    -------------------- Session and authentication ---------------------
    ------------------- Packetizer ----------------   --- FIXME: ACK? ---
    TCP|SOCKS|HTTP CONNECT|HTTP Websocket|HTTP BOSH | HTTP plain|ICMP|DNS

The shows that there's two types of lower layers: Those that provide a stream, and those that provide a message/packet interface. Stream layers are processed through a packetizer that splits the stream on message boundaries (by prepedin each message with the message length).

FIXME: Stream layers generally provide receipt acknowledgements, message layers generally do not. This may need to be adressed by a seperate ACK layer.


### Sessions, authentication

The Client has username U and password P. Server has list of all U/P pairs. First packet from the client is a login request with the username and login request ID (LID). The server responds with a login response containing a session ID (SID) and a nonce. Both client and server calculate a session key K using a suitable KDF (FIXME: PBKDF2?) using U,P,LID,SID and nonce as inputs.
(The server will protect against DoS by allowing only one login attempt per username every few seconds.) Important: Server behaviour must be the same for existing vs. non-existing usernames!

All packets except for the login and login response are associated with a SID and therefore K and will be protected with a 8-byte MAC M (FIXME: truncated HMAC-SHA256?). Packets that fail authentication will be silently discarded. All packets have a 3-byte sequence number C and will only be processed in sequence (FIXME: rolling window?). Replayed packets are discarded. Exception: If a packet that elicited a response is re-received, the response will be re-sent, over the same mechanism that the new copy of the packet was receive. (FIXME: Defined reasonable boundaries) This allows the client to send a packet using multiple means and receive the response over any working lower layer.

### Control, Payload 

The highest layer is a simple but feature-complete port-forwarding/connection system. A client may request an outgoing connection from the server to an IP address/port (IPv4/IPv6) and will be given a response with a connection ID (CID). Alternatively the client may request listening on a port on the server and will be given a port ID (PID). When an incoming connection is made to the port the client will receive a message from the server mapping the PID to a new CID.
Finally, both sides may send data packets for any open CID.

### Basic packet format

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|L    |       4 |  uint, le |  packet length, only used with stream transports         |
|T    |       1 |  uint     |  packet type, bit 0: sent from server, bit 7 is reserved |
|SID  |       4 |  opaque   |  session ID                                              |
|C    |       3 |  uint, le |  packet sequence number                                  |
|M    |       8 |  opaque   |  packet HMAC                                             |

Not all items are transmitted in all packets: For packet based lower layers, the L is implicit and not transmitted. SID,C,M are not valid for login/login response packets and not transmitted. Certain lower layers may transmit some of these fields out-of-band, e.g. as HTTP parameters.

## Message types

### T=0 Login

Note: This message does not have SID, C, or M

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|LID  |      16 | opaque    |  Login ID, used to match the server response             |
|V    |       2 | two uint  |  requested protocol version as two integers major.minor  |
|UID  |       x | UTF-8     |  user name                                               |

### T=1 Login response

Note: This message does not have SID, C, or M

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|LID  |      16 | opaque    |  Login ID, copied from the login message                 |
|V    |       2 | two uint  |  used protocol version as two integers                   |
|nonce|      16 | opaque    |  server's login nonce                                    |


