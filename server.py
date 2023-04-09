#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""
import argparse
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import nacl.utils
from nacl.secret import SecretBox
from nacl.public import PrivateKey, Box
from nacl.pwhash import argon2i
password_size = 32  # Specify the password size in bytes
password = nacl.utils.random(password_size)
salt = nacl.utils.random(argon2i.SALTBYTES)
symmetric_key = argon2i.kdf(SecretBox.KEY_SIZE, password, salt=salt, opslimit=nacl.pwhash.argon2i.OPSLIMIT_INTERACTIVE, memlimit=nacl.pwhash.argon2i.MEMLIMIT_INTERACTIVE)


def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    global symmetric_key
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        #Has to send request to recieve public key
        # Generate a new private key for the server
        server_private_key = PrivateKey.generate()

        # Create a new box with the server's private key and the client's public key
        def create_server_box(client_public_key):
            return Box(server_private_key, client_public_key)

        # Wait for a connection from the client
        
        client_public_key_bytes = client.recv(BUFSIZ)
        client_public_key = nacl.public.PublicKey(client_public_key_bytes)

        # Generate a new symmetric key
        # Encrypt the symmetric key with the client's public key and send it back to the client
        server_box = create_server_box(client_public_key)
        encrypted_symmetric_key = server_box.encrypt(symmetric_key)
        client.send(encrypted_symmetric_key)

        server_public_key_bytes = server_private_key.public_key.encode()
        client.send(server_public_key_bytes)
        # Use the symmetric key for further communication with the client
        client.recv(BUFSIZ)
        box = SecretBox(symmetric_key)
        
        client.send(box.encrypt(b"Greetings from the cave! Now type your name and press enter!"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""

    encrypted_name = client.recv(BUFSIZ)
    box = SecretBox(symmetric_key)
    name = box.decrypt(encrypted_name).decode("utf-8")
    # SEnds back to a client
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    
    enc_welcome = box.encrypt(bytes(welcome,"utf8"))
    client.send(enc_welcome)
    # Send the encrypted message over the network
    
    #Sends to rest of clients
    msg = "%s has joined the chat!" % name
    msg = box.encrypt(bytes(msg,"utf8"))
    broadcast(msg)
    clients[client] = name

    while True:
        msg = client.recv(BUFSIZ)
        if msg != bytes("{quit}", "utf8"):
            broadcast(msg, name+": ")
        else:
            client.send(box.encrypt(bytes("{quit}", "utf8")))
            client.close()
            del clients[client]
            broadcast(box.encrypt(bytes("%s has left the chat." % name, "utf8")))
            break


def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    box = SecretBox(symmetric_key)
    msg = box.decrypt(msg).decode("utf-8")
    for sock in clients:
        sock.send(box.encrypt(bytes(prefix+msg,"utf8")))

        
clients = {}
addresses = {}


#----Now comes the arguments part----
parser = argparse.ArgumentParser(description='This is the server for the chat.')
parser.add_argument('ip', type=str, nargs='?', default='127.0.0.1',
                    help='the ip you want to bind. (default 127.0.0.1)')

parser.add_argument('-p','--port', type=int, nargs='?', default=33000,
                    help='the port. (default 33000)')  
parser.add_argument('-s','--buff-size', type=int, nargs='?', default=1024,
                    help='the size of the buffer. (default 1024)')
                    
args = parser.parse_args()
HOST=args.ip
PORT=args.port 
BUFSIZ = args.buff_size

ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    SERVER.listen(5)
    print(f'[INFO] Server started on {HOST}:{PORT}, buffer size: {BUFSIZ}')
    print("Waiting for connection...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
