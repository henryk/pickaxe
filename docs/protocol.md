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

All packets except for the login and login response are associated with a SID and therefore K and will be protected with a 8-byte MAC M (FIXME: truncated HMAC-SHA256?). Packets that fail authentication will be silently discarded. All packets have a sequence number and will only be processed in sequence (FIXME: rolling window?). Replayed packets are discarded. Exception: If a packet that elicited a response is re-received, the response will be re-sent, over the same mechanism that the new copy of the packet was received. (FIXME: Defined reasonable boundaries) This allows the client to send a packet using multiple means and receive the response over any working lower layer. A packet will be resent until it is acknowledged.

*Sequence number truncation*: Internally the sequence numbers C and a are a 64-bit unsigned integer. For transmission they are truncated to the least significant 16 bits, called C' and A'. The recipient of a packet fills the upper 48 bits by looking at the expected sequence number (handling overflows as necessary). The HMAC calculation includes the full 64-bit sequence numbers!

### Control, Payload 

The highest layer is a simple but feature-complete port-forwarding/connection system. A client may request an outgoing connection from the server to an IP address/port (IPv4/IPv6) and will be given a response with a connection ID (CID). Alternatively the client may request listening on a port on the server and will be given a port ID (PID). When an incoming connection is made to the port the client will receive a message from the server mapping the PID to a new CID.
Finally, both sides may send data packets for any open CID.

### Basic packet format

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|L    |       4 |  uint, le |  packet length, only used with stream transports         |
|T    |       1 |  uint     |  packet type, bit 0: sent from server, bit 7 is reserved |
|SID  |       4 |  opaque   |  session ID                                              |
|C'   |       2 |  uint, le |  packet sequence number, truncated                       |
|A'   |       2 |  uint, le |  packet acknowledgement number, truncated                |
|M    |       8 |  opaque   |  packet HMAC                                             |

Not all items are transmitted in all packets: For packet based lower layers, the L is implicit and not transmitted. SID,C,A,M are not valid for login/login response packets and not transmitted. Certain lower layers may transmit some of these fields out-of-band, e.g. as HTTP parameters.

## Message types

### T=0 Login

Note: This message does not have SID, C, A, or M

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|LID  |      16 | opaque    |  Login ID, used to match the server response             |
|V    |       2 | two uint  |  requested protocol version as two integers major.minor  |
|UID  |       x | UTF-8     |  user name                                               |

### T=1 Login response

Note: This message does not have SID, C, A, or M

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|LID  |      16 | opaque    |  Login ID, copied from the login message                 |
|V    |       2 | two uint  |  used protocol version as two integers                   |
|nonce|      16 | opaque    |  server's login nonce                                    |

### T=2 Connect

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|PID  |      16 | opaque    | Pending port ID                                          |
|Proto|       1 | uint      | Protocol identifier: 4=IPv4, 6=IPv6                      |
|Port |       2 | uint, le  | TCP port number to connect to                            |
|Target|      x | UTF-8     | Protocol specific address or name                        |

### T=3 Connect response

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|PID  |      16 | opaque    | Pending port ID, copied from request                     |
|CID  |       4 | opaque    | Connection ID                                            |
|Status|      1 | uint      |                                                          |

### T=4 Listen

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|PID  |      16 | opaque    | Pending port ID                                          |
|Config|      1 | uint      | Indicates whether a specific or random port should be used|
|Port |       2 | uint, le  | TCP port to listen on                                    |

### T=5 Listen response

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|PID  |      16 | opaque    | Pending port ID, copied from request                     |
|Status|      1 | uint      |                                                          |
|Port |       2 | uint, le  | TCP that's listened on                                   |

### T=6 Stop listen

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|PID  |      16 | opaque    | Pending port ID, copied from request                     |
|Status|      1 | uint      |                                                          |

### T=7 Accept

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|PID  |      16 | opaque    | Pending port ID, copied from request                     |
|CID  |       4 | opaque    | Connection ID                                            |
|Status|      1 | uint      |                                                          |

### T=8/9 Close conn

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|CID  |       4 | opaque    | Connection ID                                            |
|Status|      1 | uint      |                                                          |

### T=10/11 Data

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|CID  |       4 | opaque    | Connection ID                                            |
|Data |       x | opaque    | Payload                                                  |

### T=12/13 Keep alive/Echo

|name |  length |  type     |  description                                             |
|-----|--------:|-----------|----------------------------------------------------------|
|Type |       1 | uint      |                                                          |
|EID  |     16? | opaque    | Echo ID, only for echo                                   |
|Data |      x? | opaque    | Echo data, only for echo                                 |

### T=126/127 Disconnect

No further fields
