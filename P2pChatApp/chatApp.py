# -*- coding: utf-8 -*-
"""
Created on Fri Jun  7 01:06:58 2024

@author: User
"""

import socket
import threading
import hashlib
import sqlite3
from crypto_utils import generate_keys, sign_message, verify_signature
from cryptography.hazmat.primitives import serialization

# Initialize the database
def initialize_db():
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        print(f"User {username} registered successfully.")
    except sqlite3.IntegrityError:
        print(f"Username {username} is already taken.")
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('chat_app.db')
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute('SELECT id FROM users WHERE username = ? AND password = ?', (username, hashed_password))
    user = cursor.fetchone()
    conn.close()
    if user:
        print(f"User {username} authenticated successfully.")
        return True
    else:
        print(f"Authentication failed for user {username}.")
        return False

initialize_db()

# Generate keys for the user
private_key, public_key = generate_keys()

def handle_receive(client_socket, peer_public_key):
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                print("Connection closed by the peer.")
                break

            msg_len = int.from_bytes(message[:4], 'big')
            msg = message[4:4 + msg_len].decode('utf-8')
            signature = message[4 + msg_len:]

            if verify_signature(peer_public_key, msg, signature):
                print(f"Received (verified): {msg}")
            else:
                print("Received (unverified): Message signature is invalid")
        except Exception as e:
            print(f"Receive error: {e}")
            break
    client_socket.close()

def handle_send(client_socket):
    while True:
        try:
            message = input("Enter message: ")
            if not message:
                print("Empty message, closing connection.")
                break
            
            signature = sign_message(private_key, message)
            msg_len = len(message).to_bytes(4, 'big')
            client_socket.send(msg_len + message.encode('utf-8') + signature)
        except OSError as e:
            print(f"Socket error in send: {e}")
            break
        except Exception as e:
            print(f"General error in send: {e}")
            break
    client_socket.close()

def start_peer(listen_port, connect_ip=None, connect_port=None):
    username = input("Username: ")
    password = input("Password: ")

    if not authenticate_user(username, password):
        print("Authentication failed. Exiting.")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', listen_port))
    server_socket.listen(5)
    print(f"Listening on port {listen_port}")

    client_socket = None
    peer_public_key = None
    if connect_ip and connect_port:
        client_socket, peer_public_key = connect_to_peer(connect_ip, connect_port)
        if not client_socket:
            print("Failed to connect to peer.")
            server_socket.close()
            return
    else:
        print("Waiting for a connection...")
        client_socket, addr = server_socket.accept()
        peer_public_key = exchange_keys(client_socket)
        print(f"Connected to {addr}")

    if client_socket:
        receive_thread = threading.Thread(target=handle_receive, args=(client_socket, peer_public_key,))
        send_thread = threading.Thread(target=handle_send, args=(client_socket,))
        receive_thread.start()
        send_thread.start()

def connect_to_peer(ip, port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ip, port))
        peer_public_key = exchange_keys(client)
        print(f"Connected to {ip}:{port}")
        return client, peer_public_key
    except socket.error as e:
        print(f"Failed to connect to peer: {e}")
        return None, None

def exchange_keys(client_socket):
    own_public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(own_public_key_pem)

    peer_public_key_pem = client_socket.recv(1024)
    peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)
    return peer_public_key

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2:
        start_peer(int(sys.argv[1]))
    elif len(sys.argv) == 4:
        start_peer(int(sys.argv[1]), connect_ip=sys.argv[2], connect_port=int(sys.argv[3]))
    else:
        print("Usage:")
        print("  To start a listening peer: python p2p_chat.py <listen_port>")
        print("  To start a peer and connect: python p2p_chat.py <listen_port> <connect_ip> <connect_port>")
