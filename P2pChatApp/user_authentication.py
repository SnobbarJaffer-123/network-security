# -*- coding: utf-8 -*-
"""
Created on Thu Jun  6 22:45:47 2024

@author: User
"""

# user_authentication.py
import initialize_db

def interactive_user_authentication():
    username = input("Username: ")
    password = input("Password: ")
    if initialize_db.authenticate_user(username, password):
        print("Authentication successful!")
    else:
        print("Authentication failed.")

if __name__ == "__main__":
    interactive_user_authentication()
