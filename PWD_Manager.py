import tkinter as tk
from tkinter import messagebox
import random
import json
import pyperclip
from cryptography.fernet import Fernet

# Create the main application window
window = tk.Tk()
window.title("Password Manager")
window.geometry("600x400")
window.configure(bg="#f7f7f7")  # Light background color

# Title label
tk.Label(window, text="Password Manager", font=("Helvetica", 24, "bold"), bg="#f7f7f7").pack(pady=20)

# Generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Load or create the encryption key
def load_key():
    try:
        with open("key.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        return key

key = load_key()
cipher_suite = Fernet(key)

# Vernam Cipher Encryption
def vernam_encrypt(plaintext, key):
    ciphertext = ''.join([chr(ord(p) ^ ord(k)) for p, k in zip(plaintext, key)])
    return ciphertext

# Vernam Cipher Decryption
def vernam_decrypt(ciphertext, key):
    plaintext = ''.join([chr(ord(c) ^ ord(k)) for c, k in zip(ciphertext, key)])
    return plaintext

def generate_key(length):
    key = ''.join([chr(random.randint(0, 255)) for _ in range(length)])
    return key

# Encrypt password function
def encrypt_password_vernam():
    pwd = Password_Input_Admin.get()
    key = generate_key(len(pwd))
    encrypted_pwd = vernam_encrypt(pwd, key)
    admin_lbl_encrypted.config(text="Encrypted Password: " + encrypted_pwd)
    temp_vars['encrypted'] = encrypted_pwd
    temp_vars['key'] = key

# Decrypt password function
def decrypt_password_vernam():
    encrypted_pwd = temp_vars.get('encrypted', '')
    key = temp_vars.get('key', '')
    if encrypted_pwd and key:
        decrypted_pwd = vernam_decrypt(encrypted_pwd, key)
        admin_lbl_decrypted.config(text="Decrypted Password: " + decrypted_pwd)
    else:
        admin_lbl_decrypted.config(text="No encrypted password to decrypt")

def save_password():
    account = Account_Input.get()
    username = Username_Input.get()
    password = Password_Input.get()

    if not account or not username or not password:
        messagebox.showwarning("Warning", "Please fill in all fields.")
        return

    encrypted_password = cipher_suite.encrypt(password.encode()).decode()
    data = {
        "account": account,
        "username": username,
        "password": encrypted_password
    }

    try:
        with open("passwords.json", "r") as file:
            passwords = json.load(file)
    except FileNotFoundError:
        passwords = []

    passwords.append(data)

    with open("passwords.json", "w") as file:
        json.dump(passwords, file, indent=4)

    messagebox.showinfo("Info", "Password saved successfully.")

def load_password():
    account = Account_Input.get()

    if not account:
        messagebox.showwarning("Warning", "Please enter the account name.")
        return

    try:
        with open("passwords.json", "r") as file:
            passwords = json.load(file)
    except FileNotFoundError:
        messagebox.showwarning("Warning", "No passwords found.")
        return

    for data in passwords:
        if data["account"] == account:
            username = data["username"]
            password = cipher_suite.decrypt(data["password"].encode()).decode()
            Username_Input.delete(0, tk.END)
            Username_Input.insert(0, username)
            Password_Input.delete(0, tk.END)
            Password_Input.insert(0, password)
            return

    messagebox.showwarning("Warning", "No matching account found.")

def copy_to_clipboard():
    password = Password_Input.get()
    if password:
        pyperclip.copy(password)
        messagebox.showinfo("Info", "Password copied to clipboard.")
    else:
        messagebox.showwarning("Warning", "No password to copy.")

# Function to validate the PIN and open the admin window
def open_admin_window():
    pin = pin_entry.get()
    if pin == "1234":  # Change the PIN as needed
        admin_window()
    else:
        messagebox.showwarning("Warning", "Incorrect PIN")

# Function to create the admin window for encryption/decryption
def admin_window():
    admin_win = tk.Toplevel(window)
    admin_win.title("Admin - Encryption/Decryption")
    admin_win.geometry("400x300")
    admin_win.configure(bg="#eaeaea")  # Background color for admin window

    tk.Label(admin_win, text="Enter Password to Encrypt/Decrypt", bg="#eaeaea").pack(pady=10)
    
    global Password_Input_Admin
    Password_Input_Admin = tk.Entry(admin_win, show='*', width=30)
    Password_Input_Admin.pack(pady=5)

    tk.Button(admin_win, text="Encrypt (Vernam)", command=encrypt_password_vernam).pack(pady=5)
    tk.Button(admin_win, text="Decrypt (Vernam)", command=decrypt_password_vernam).pack(pady=5)

    # Labels to display encrypted and decrypted passwords in the admin window
    global admin_lbl_encrypted, admin_lbl_decrypted
    admin_lbl_encrypted = tk.Label(admin_win, text="", bg="#eaeaea")
    admin_lbl_encrypted.pack(pady=10)
    
    admin_lbl_decrypted = tk.Label(admin_win, text="", bg="#eaeaea")
    admin_lbl_decrypted.pack(pady=10)

# Create the PIN entry window
def pin_window():
    pin_win = tk.Toplevel(window)
    pin_win.title("Admin PIN")
    pin_win.geometry("300x150")
    pin_win.configure(bg="#f7f7f7")
    
    tk.Label(pin_win, text="Enter 4-Digit PIN", bg="#f7f7f7").pack(pady=10)
    
    global pin_entry
    pin_entry = tk.Entry(pin_win, show='*', width=10)
    pin_entry.pack(pady=5)

    tk.Button(pin_win, text="Submit", command=open_admin_window).pack(pady=5)

# Create and place labels and entry widgets in the main window
frame = tk.Frame(window, bg="#f7f7f7")
frame.pack(pady=20)

tk.Label(frame, text="Enter Account", bg="#f7f7f7").grid(row=0, column=0, padx=10, pady=5)
Account_Input = tk.Entry(frame, width=30)
Account_Input.grid(row=0, column=1, padx=10, pady=5)

tk.Label(frame, text="Enter Username", bg="#f7f7f7").grid(row=1, column=0, padx=10, pady=5)
Username_Input = tk.Entry(frame, width=30)
Username_Input.grid(row=1, column=1, padx=10, pady=5)

tk.Label(frame, text="Enter Password", bg="#f7f7f7").grid(row=2, column=0, padx=10, pady=5)
Password_Input = tk.Entry(frame, show='*', width=30)
Password_Input.grid(row=2, column=1, padx=10, pady=5)

# Create and place buttons for saving and loading passwords
tk.Button(frame, text="Save Password", command=save_password, bg="#4CAF50", fg="white").grid(row=3, column=0, pady=20)
tk.Button(frame, text="Load Password", command=load_password, bg="#2196F3", fg="white").grid(row=3, column=1, pady=20)
# Create and place the button for copying to clipboard
tk.Button(frame, text="Copy to Clipboard", command=copy_to_clipboard, bg="#FFC107").grid(row=4, columnspan=2, pady=10)
# Create the button to open the PIN window
tk.Button(window, text="Admin", command=pin_window, bg="#FF5722", fg="white").pack(pady=10)
# Temporary variable storage
temp_vars = {}
# Run the main event loop
window.mainloop()
