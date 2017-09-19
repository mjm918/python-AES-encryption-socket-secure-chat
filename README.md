# python-AES-encryption-socket-secure-chat

# Objectives:
On completion of this assignment you should be able to:
•	Understand some basic concepts in cryptography and networking
•	Understand key transport and secure communication.
•	Understand network programming.
•	Applying AES and Key Exchange concepts.
•	Applying MD5 hash for integrity checking of key.

# Language Used: 
Python 2.7 (Download Link: https://www.python.org/downloads/ ) 

# Library Used: 
*PyCrypto (Download Link: https://pypi.python.org/pypi/pycrypto ) 
*PyCryptoPlus (Download Link: https://github.com/doegox/python-cryptoplus ) 
	*Lazyme (Download Link: https://pypi.python.org/pypi/lazyme)

# Library Installation: 

# PyCrypto: 
  Unzip the file. Go to the directory and open terminal for linux(alt+ctrl+t) and CMD(shift+right click+select command prompt open here) for windows. After that write python setup.py install (Make Sure Python Environment is set properly in Windows OS)    

# PyCryptoPlus & Lazyme: 
  Same as the last library. Files: *server.py (Server-Side Coding) *client.py (Client-Side Coding)

# Task Implementation:

# SOCKET SETUP:
* As the creating public and private keys as well as hashing the public key, we need to setup the socket now. For setting up the socket, we need to import another module with “import socket” and connect (for client) or bind (for server) the IP address and the port with the socket getting from the user.

# Client side:
	 `server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((host, port))`


# Server side:
    `server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)`

‘socket.SO_REUSEADDR’ is used for releasing the port after quitting the server, so that we can use the same port every time. “socket.AF_INET,socket.SOCK_STREAM” will allow us to use accept() function and messaging fundamentals.

# Client-Server codes, key exchange protocol and the shared key computations:

	First of all, server will generate RSA private, public key and also generate the eight byte session key and hash of it to make it readable.
    
    `# public key and private key
    random = Random.new().read
    RSAkey = RSA.generate(1024, random)
    public = RSAkey.publickey().exportKey()
    private = RSAkey.exportKey()

    tmpPub = hashlib.md5(public)
    my_hash_public = tmpPub.hexdigest()

    eightByte = os.urandom(8)
    sess = hashlib.md5(eightByte)
    session = sess.hexdigest()`


At the same time, client will also generate RSA private, public key. ‘random’ is derived from “from Crypto import Random” module. RSAkey is derived from “from Crypto.PublicKey import RSA” which will create a private key, size of 1024 by generating random characters. Public is exporting public key from previously generated private key. After creating the public and private key, we have to hash the public key to send over to the server using ‘md5’ hash. To use the ‘md5’ hash we need to import another module by writing “import hashlib”. 
In both side, the public and private keys will be stored in separate text files. 

`Client:`
	After preparing the RSA keys, client will send the public key and public key hash to server and wait for server to send back the session key that prepared earlier.

`Server:`
	Server will get the public key and public key hash from client and compare them for integrity checking. If the comparison is matched, the server will proceed for further operations. Otherwise, the connection will be declined immediately.  Then the session key will be generated. Server will send the session key, hash of session key, public key and hash of public key. For all kind of hashing, md5 hashing will be used. In this case, server will combine all the keys and hashes with delimiter (“:”)

	         `clientPublic = RSA.importKey(tmpClientPublic)
                fSend = eightByte + ":" + session + ":" + my_hash_public
                fSend = clientPublic.encrypt(fSend, None)
                client.send(str(fSend) + ":" + public)`
`Client:`
	As soon as the client receives the keys and hash, it will decrypt with the private key and split the response from server and split them by delimiter (“:”). Then it will compare the public key and hash of public key from the server for integrity checking. After that, it will send the encrypted session key to server and wait for confirmation response.

	     `serverPublic = RSA.importKey(serverPublic).encrypt(eightByte, None)
            server.send(str(serverPublic))`

`Server:`
	In the server side, it will check the session key from client and if it matches the original session key that created earlier, server will send a flag “Ready” to client. The flag is a confirmation that connection is established and server is ready to communicate. The flag will be encrypted with 128 byte AES encryption. The key of AES encryption will be the session key and reverse of session key to make it 16bit long. The 16 bit long key will also be the IV in this case.
		`key_128 = eightByte + eightByte[::-1]
              AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
              clientMsg = AESKey.encrypt(Padding(FLAG_READY))`



Upon receiving the “Ready” flag, both server and client side are ready to communicate. Later on, all the encryption and decryption will be done with the generated AES key. For sending and receiving message, both sides are using multi-threading so that the chat can be done in real time.
	`Client:`
		  `threading_rec = threading.Thread(target=ReceiveMessage)
                threading_rec.start()
                threading_send = threading.Thread(target=SendMessage)
                threading_send.start()`

	`Server:`
		  `threading_client.start()
threading_message =   threading.Thread(target=send_message,args=[client,AESKey])
                threading_message.start()`
