# -*- coding: utf-8 -*-
"""
Created on Thu Jun  6 22:41:31 2024

@author: User
"""

# user_registration.py
import initialize_db

def interactive_user_registration():
    while True:
        username = input("Enter username (or 'exit' to quit): ")
        if username.lower() == 'exit':
            break
        password = input("Enter password: ")
        initialize_db.register_user(username, password)
        print()

if __name__ == "__main__":
    interactive_user_registration()
