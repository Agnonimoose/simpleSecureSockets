# Simple Secure Sockets
Stub snippet of a client/server pair of secure TCP sockets, module contains 2 classes that work as a pair.


### server 

Used to create a server connection that the client class can interact with using the send() and recv() methods.

```
class server:
	def __init__(self, ip:str, port:int, key=None, RSA=False, socket_timeout=.5):

	def create_secure_connection(self, rsa_enabled: bool) -> bool:
		Uses RSA cryptography to automatically share a key between the server and client, for use in symmetric encryption for any future messages
		
	def send(self, data: any) -> bool:
		Sends the data
		
	def recv() -> any:
		Ensures successful receival of data sent from the 'send' method			   

	def __del__(self) -> bool:
		Automatically closes the connection between the client and server upon the programs end.
```

### client

Used to connect to an active server created by the server class, interactions can be made using the send() and recv() methods.

```
class client(server):

	def __init__(self, ip:str, port:int, key=None, socket_timeout=.5):

	def create_secure_connection(self) -> bool:
		Uses RSA cryptography to share a symmetric key between the server and client, for use in symmetric encryption for future messages

	def send(self, data: any) -> bool:
		Inherited from server
	
	def recv() -> any:
		Inherited from server
	
	def __del__(self) -> bool:
		Inherited from server
	
```
