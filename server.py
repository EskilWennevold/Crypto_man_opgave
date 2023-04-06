#!/usr/bin/env python3
"""Server for multithreaded (asynchronous) chat application."""
import argparse
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_CBC)
iv = cipher.iv
def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        client.send(bytes(f"Greetings from the cave! Now type your name and press enter!::{key.hex()}::{cipher.iv.hex()}", "utf8"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""

    name = client.recv(BUFSIZ)
    decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    name = decrypt_cipher.decrypt(name)
    name = unpad(name).decode('utf-8')
    # SEnds back to a client
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit.' % name
    encrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_msg = pad(welcome.encode("utf-8"), AES.block_size)
    encrypted_msg = encrypt_cipher.encrypt(padded_msg)
    # Send the encrypted message over the network
    client.send(encrypted_msg)
    #Sends to rest of clients
    msg = "%s has joined the chat!" % name
    encrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_msg = pad(msg.encode("utf-8"), AES.block_size)
    encrypted_msg1 = encrypt_cipher.encrypt(padded_msg)
    broadcast(encrypted_msg1)
    clients[client] = name

    while True:
        msg = client.recv(BUFSIZ)
        if msg != bytes("{quit}", "utf8"):
            broadcast(msg, name+": ")
        else:
            client.send(bytes("{quit}", "utf8"))
            client.close()
            del clients[client]
            broadcast(bytes("%s has left the chat." % name, "utf8"))
            break

def pad(s, block_size):
    """Pads a string s with bytes to make its length a multiple of block_size."""
    padding_len = block_size - len(s) % block_size
    if padding_len == 0:
        padding_len = block_size
    padding = bytes([padding_len] * padding_len)
    return s + padding

def unpad(s):
    """Removes padding from string s."""
    padding_len = s[-1]
    return s[:-padding_len]

def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    #Unecrypts the message
    decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_msg = decrypt_cipher.decrypt(msg)
    un_enc_msg = unpad(encrypted_msg).decode('utf-8')
    new_msg = prefix+un_enc_msg
    encrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_msg = pad(new_msg.encode("utf-8"), AES.block_size)
    encrypted_msg1 = encrypt_cipher.encrypt(padded_msg)
    for sock in clients:
        sock.send(encrypted_msg1)

        
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
