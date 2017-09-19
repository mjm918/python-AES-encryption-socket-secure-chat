import socket
import os
import threading
import hashlib
from Crypto import Random
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
import signal
from lazyme.string import color_print


def RemovePadding(s):
    return s.replace('`','')


def Padding(s):
    return s + ((16 - len(s) % 16) * '`')


def ReceiveMessage():
    while True:
        emsg = server.recv(1024)
        msg = RemovePadding(AESKey.decrypt(emsg))
        if msg == FLAG_QUIT:
            color_print("\n[!] Server was shutdown by admin", color="red", underline=True)
            os.kill(os.getpid(), signal.SIGKILL)
        else:
            color_print("\n[!] Server's encrypted message \n" + emsg, color="gray")
            print "\n[!] SERVER SAID : ", msg


def SendMessage():
    while True:
        msg = raw_input("[>] YOUR MESSAGE : ")
        en = AESKey.encrypt(Padding(msg))
        server.send(str(en))
        if msg == FLAG_QUIT:
            os.kill(os.getpid(), signal.SIGKILL)
        else:
            color_print("\n[!] Your encrypted message \n" + en, color="gray")


if __name__ == "__main__":
    #objects
    server = ""
    AESKey = ""
    FLAG_READY = "Ready"
    FLAG_QUIT = "quit"
    # 10.1.236.227
    # public key and private key
    random = Random.new().read
    RSAkey = RSA.generate(1024, random)
    public = RSAkey.publickey().exportKey()
    private = RSAkey.exportKey()

    tmpPub = hashlib.md5(public)
    my_hash_public = tmpPub.hexdigest()

    print public
    print "\n",private

    host = raw_input("Host : ")
    port = int(input("Port : "))
#    host = "127.0.0.1"
#    port = 5599

    with open('private.txt', 'w'):
        pass
    with open('public.txt', 'w'):
        pass

    try:
        file = open('private.txt', 'w')
        file.write(private)
        file.close()

        file = open('public.txt', 'w')
        file.write(public)
        file.close()
    except BaseException:
        color_print("Key storing in failed", color="red", underline=True)

    check = False

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((host, port))
        check = True
    except BaseException:
        color_print("\n[!] Check Server Address or Port", color="red", underline=True)

    if check is True:
        color_print("\n[!] Connection Successful", color="green", bold=True)
        server.send(public + ":" + my_hash_public)
        # receive server public key,hash of public,eight byte and hash of eight byte
        fGet = server.recv(4072)
        split = fGet.split(":")
        toDecrypt = split[0]
        serverPublic = split[1]
        color_print("\n[!] Server's public key\n", color="blue")
        print serverPublic
        decrypted = RSA.importKey(private).decrypt(eval(toDecrypt.replace("\r\n", '')))
        splittedDecrypt = decrypted.split(":")
        eightByte = splittedDecrypt[0]
        hashOfEight = splittedDecrypt[1]
        hashOfSPublic = splittedDecrypt[2]
        color_print("\n[!] Client's Eight byte key in hash\n", color="blue")
        print hashOfEight

        # hashing for checking
        sess = hashlib.md5(eightByte)
        session = sess.hexdigest()

        hashObj = hashlib.md5(serverPublic)
        server_public_hash = hashObj.hexdigest()
        color_print("\n[!] Matching server's public key & eight byte key\n", color="blue")
        if server_public_hash == hashOfSPublic and session == hashOfEight:
            # encrypt back the eight byte key with the server public key and send it
            color_print("\n[!] Sending encrypted session key\n", color="blue")
            serverPublic = RSA.importKey(serverPublic).encrypt(eightByte, None)
            server.send(str(serverPublic))
            # creating 128 bits key with 16 bytes
            color_print("\n[!] Creating AES key\n", color="blue")
            key_128 = eightByte + eightByte[::-1]
            AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
            # receiving ready
            serverMsg = server.recv(2048)
            serverMsg = RemovePadding(AESKey.decrypt(serverMsg))
            if serverMsg == FLAG_READY:
                color_print("\n[!] Server is ready to communicate\n", color="blue")
                serverMsg = raw_input("\n[>] ENTER YOUR NAME : ")
                server.send(serverMsg)
                threading_rec = threading.Thread(target=ReceiveMessage)
                threading_rec.start()
                threading_send = threading.Thread(target=SendMessage)
                threading_send.start()
        else:
            color_print("\nServer (Public key && Public key hash) || (Session key && Hash of Session key) doesn't match", color="red", underline=True)
