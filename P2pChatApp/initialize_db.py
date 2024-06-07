# -*- coding: utf-8 -*-
"""
Created on Thu Jun  6 22:37:31 2024

@author: User
"""

import sqlite3
import hashlib

def initialize_db():
    """
    Initialize the SQLite database and create the users table if it doesn't exist.
    """
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
    """
    Hash the given password using SHA-256.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    """
    Register a new user with the given username and password.
    """
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
    """
    Authenticate a user with the given username and password.
    """
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

# Initialize the database
initialize_db()
