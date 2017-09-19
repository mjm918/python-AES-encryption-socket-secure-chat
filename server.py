import socket
import os
import signal
import threading
import hashlib
import fcntl
import struct
from Crypto import Random
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
from lazyme.string import color_print


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', ifname[:15])
    )[20:24])


def RemovePadding(s):
    return s.replace('`','')


def Padding(s):
    return s + ((16 - len(s) % 16) * '`')


def ConnectionSetup():
    while True:
        if check is True:
            client, address = server.accept()
            color_print("\n[!] One client is trying to connect...", color="green", bold=True)
            # get client public key and the hash of it
            clientPH = client.recv(2048)
            split = clientPH.split(":")
            tmpClientPublic = split[0]
            clientPublicHash = split[1]
            color_print("\n[!] Anonymous client's public key\n",color="blue")
            print tmpClientPublic
            tmpClientPublic = tmpClientPublic.replace("\r\n", '')
            clientPublicHash = clientPublicHash.replace("\r\n", '')
            tmpHashObject = hashlib.md5(tmpClientPublic)
            tmpHash = tmpHashObject.hexdigest()

            if tmpHash == clientPublicHash:
                # sending public key,encrypted eight byte ,hash of eight byte and server public key hash
                color_print("\n[!] Anonymous client's public key and public key hash matched\n", color="blue")
                clientPublic = RSA.importKey(tmpClientPublic)
                fSend = eightByte + ":" + session + ":" + my_hash_public
                fSend = clientPublic.encrypt(fSend, None)
                client.send(str(fSend) + ":" + public)

                clientPH = client.recv(2048)
                if clientPH != "":
                    clientPH = RSA.importKey(private).decrypt(eval(clientPH.decode('utf-8')))
                    color_print("\n[!] Matching session key\n", color="blue")
                    if clientPH == eightByte:
                        # creating 128 bits key with 16 bytes
                        color_print("\n[!] Creating AES key\n", color="blue")
                        key_128 = eightByte + eightByte[::-1]
                        AESKey = AES.new(key_128, AES.MODE_CBC,IV=key_128)
                        clientMsg = AESKey.encrypt(Padding(FLAG_READY))
                        client.send(clientMsg)
                        color_print("\n[!] Waiting for client's name\n", color="blue")
                        # client name
                        clientMsg = client.recv(2048)
                        CONNECTION_LIST.append((clientMsg, client))
                        color_print("\n"+clientMsg+" IS CONNECTED", color="green", underline=True)
                        threading_client = threading.Thread(target=broadcast_usr,args=[clientMsg,client,AESKey])
                        threading_client.start()
                        threading_message = threading.Thread(target=send_message,args=[client,AESKey])
                        threading_message.start()
                    else:
                        color_print("\nSession key from client does not match", color="red", underline=True)
            else:
                color_print("\nPublic key and public hash doesn't match", color="red", underline=True)
                client.close()


def send_message(socketClient,AESk):
    while True:
        msg = raw_input("\n[>] ENTER YOUR MESSAGE : ")
        en = AESk.encrypt(Padding(msg))
        socketClient.send(str(en))
        if msg == FLAG_QUIT:
            os.kill(os.getpid(), signal.SIGKILL)
        else:
            color_print("\n[!] Your encrypted message \n" + en, color="gray")


def broadcast_usr(uname, socketClient,AESk):
    while True:
        try:
            data = socketClient.recv(1024)
            en = data
            if data:
                data = RemovePadding(AESk.decrypt(data))
                if data == FLAG_QUIT:
                    color_print("\n"+uname+" left the conversation", color="red", underline=True)
                else:
                    b_usr(socketClient, uname, data)
                    print "\n[!] ", uname, " SAID : ", data
                    color_print("\n[!] Client's encrypted message\n" + en, color="gray")
        except Exception as x:
            print(x.message)
            break


def b_usr(cs_sock, sen_name, msg):
    for client in CONNECTION_LIST:
        if client[1] != cs_sock:
            client[1].send(sen_name)
            client[1].send(msg)


if __name__ == "__main__":
    # objects
    host = ""
    port = 0
    server = ""
    AESKey = ""
    CONNECTION_LIST = []
    FLAG_READY = "Ready"
    FLAG_QUIT = "quit"
    YES = "1"
    NO = "2"

    # 10.1.236.227
    # public key and private key
    random = Random.new().read
    RSAkey = RSA.generate(1024, random)
    public = RSAkey.publickey().exportKey()
    private = RSAkey.exportKey()

    tmpPub = hashlib.md5(public)
    my_hash_public = tmpPub.hexdigest()

    eightByte = os.urandom(8)
    sess = hashlib.md5(eightByte)
    session = sess.hexdigest()

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
    color_print("[1] Auto connect by with broadcast IP & PORT\n[2] Manually enter IP & PORT\n", color="blue", bold=True)
    ask = raw_input("[>] ")
    if ask == YES:
        host = get_ip_address('wlp2s0')
        port = 8080
    elif ask == NO:
        host = raw_input("Host : ")
        port = int(input("Port : "))
    else:
        color_print("[!] Invalid selection", color="red", underline=True)
        os.kill(os.getpid(), signal.SIGKILL)

    print "\n",public,"\n\n",private
    color_print("\n[!] Eight byte session key in hash\n", color="blue")
    print session
    color_print("\n[!] Server IP "+host+" & PORT "+str(port), color="green", underline=True)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    color_print("\n[!] Server Connection Successful", color="green", bold=True)
    check = True
    # accept clients
    threading_accept = threading.Thread(target=ConnectionSetup)
    threading_accept.start()





