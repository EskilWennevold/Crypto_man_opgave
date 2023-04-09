#!/usr/bin/env python3
"""Script for Tkinter GUI chat client."""
import argparse
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
from nacl.secret import SecretBox
from nacl.public import PrivateKey, PublicKey, Box
title_chat = 'Chatter'
symmetric_key = None

def receive():
    """Handles receiving of messages."""
    global title_chat, symmetric_key
    while True:
        try:
            if symmetric_key == None:
                # Generate a public/private key pair in the client
                client_private_key = PrivateKey.generate()
                client_public_key = client_private_key.public_key

                # Send the client public key to the server (for example, using a socket connection)
                client_socket.send(client_public_key.encode())

                # Receive the encrypted symmetric key from the server
                encrypted_symmetric_key_bytes = client_socket.recv(BUFSIZ)
                encrypted_symmetric_key = encrypted_symmetric_key_bytes.hex()

                # Decrypt the symmetric key using the client's private key and the server's public key
                server_public_key_bytes = client_socket.recv(BUFSIZ)
                server_public_key = PublicKey(server_public_key_bytes)
                client_box = Box(client_private_key, server_public_key)
                symmetric_key = client_box.decrypt(bytes.fromhex(encrypted_symmetric_key))

                
                client_socket.send(b"hello")
                msg = client_socket.recv(BUFSIZ)
                box = SecretBox(symmetric_key)
                msg = box.decrypt(msg).decode()
            else:
                encrypted_msg = client_socket.recv(BUFSIZ)
                box = SecretBox(symmetric_key)
                decoded_msg = box.decrypt(encrypted_msg).decode("utf-8")
                msg = decoded_msg
            msg_list.insert(tkinter.END, msg)
            if msg.startswith('Welcome') and title_chat == 'Chatter':
                title_chat += ' ' + msg.split()[1]
                top.title(title_chat)
        except OSError:  # Possibly client has left the chat.
            break


def send(event=None):  # event is passed by binders.
    """Handles sending of messages."""
    msg = my_msg.get()
    my_msg.set("")  # Clears input field.
    #client_socket.send(bytes(msg, "utf8"))
    if msg == "{quit}":
        client_socket.close()
        top.quit()
    else:
        # Encrypt the message using the cipher
        box = SecretBox(symmetric_key)
        encrypted_msg = box.encrypt(bytes(msg,"utf8"))
        # Send the encrypted message over the network
        client_socket.send(encrypted_msg)


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    my_msg.set("{quit}")
    send()

top = tkinter.Tk()
top.title(title_chat)

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Username?")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
# Following will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()


entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)

#----Now comes the arguments part----
parser = argparse.ArgumentParser(description='This is the client for the chat.')
parser.add_argument('ip', type=str, nargs='?', default='127.0.0.1',
                    help='the ip you want to connect to. (default 127.0.0.1)')

parser.add_argument('-p','--port', type=int, nargs='?', default=33000,
                    help='the port. (default 33000)')  
parser.add_argument('-s','--buff-size', type=int, nargs='?', default=1024,
                    help='the size of the buffer. (default 1024)')
                    
args = parser.parse_args()
HOST=args.ip
PORT=args.port 
BUFSIZ = args.buff_size
ADDR = (HOST, PORT)

#----Now comes the sockets part----
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)
print(f'[INFO] Connected to {HOST}:{PORT}, buffer size: {BUFSIZ}')
receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.
