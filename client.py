#!/usr/bin/env python3
"""Script for Tkinter GUI chat client."""
import argparse
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
from Crypto.Cipher import AES
title_chat = 'Chatter'
key = None
iv = None

def receive():
    """Handles receiving of messages."""
    global title_chat, key, cipher, iv
    while True:
        try:
            if key == None:
                msg = client_socket.recv(BUFSIZ).decode("utf-8")
                # Split the message into parts using the '::' delimiter
                msg_parts = msg.split("::")
                # Extract the key from the message and convert it back to bytes
                iv = bytes.fromhex(msg_parts[2])
                key= bytes.fromhex(msg_parts[1])
                msg = msg_parts[0]
            else:
                encrypted_msg = client_socket.recv(BUFSIZ)

                if len(encrypted_msg) % 16 != 0:
                    print(len(encrypted_msg))
                    print(len(encrypted_msg)%16)
                decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_msg = decrypt_cipher.decrypt(encrypted_msg)
                decoded_msg = unpad(decrypted_msg).decode('utf-8')
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
        encrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
        # Encrypt the message using the cipher
        padded_msg = pad(msg.encode("utf-8"), AES.block_size)
        encrypted_msg = encrypt_cipher.encrypt(padded_msg)
        # Send the encrypted message over the network
        client_socket.send(encrypted_msg)

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
