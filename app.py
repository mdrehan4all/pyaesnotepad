import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib

# Your Password
password = 'Your@@Password'

# 32-byte hash string from input text
def generate_md5_hash(input_string):
    encoded_string = input_string.encode('utf-8')
    md5_hash_object = hashlib.md5()
    md5_hash_object.update(encoded_string)
    hex_digest = md5_hash_object.hexdigest()
    return hex_digest

# --- AES Encryption/Decryption --- #
# 32-byte key for AES-256
key = generate_md5_hash(password).encode('utf-8')

backend = default_backend()

def encrypt_data(data):
    """Encrypts data using AES-256-GCM."""
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    
    # Generate a random 12-byte nonce (number used once)
    nonce = os.urandom(12)
    
    # Create the cipher object and encryptor
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()
    
    # Encrypt the data and get the tag
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Return the nonce and the encrypted data (with tag)
    return nonce, ciphertext, encryptor.tag

def decrypt_data(nonce, ciphertext, tag):
    """Decrypts data using AES-256-GCM."""
    try:
        # Create the cipher object and decryptor
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data.decode('utf-8')
    except Exception as e:
        messagebox.showerror("Decryption Error", f"Failed to decrypt file: {e}")
        return None

# --- Global Variables ---
current_file = None

# --- Notepad Functions ---
def new_file():
    """Clears the text area to start a new file."""
    global current_file
    text_area.delete(1.0, tk.END)
    root.title("Notepad - Untitled (AES Encrypted)")
    current_file = None

def open_file():
    """Opens an AES encrypted file and loads its decrypted content."""
    global current_file
    file_path = filedialog.askopenfilename(
        defaultextension=".aes",
        filetypes=[("AES Encrypted Files", "*.enc"), ("All Files", "*.*")]
    )
    if not file_path:
        return
    
    try:
        # Read the nonce, ciphertext, and tag from the file
        with open(file_path, "rb") as f:
            nonce = f.read(12)  # Read the 12-byte nonce
            tag = f.read(16)    # Read the 16-byte authentication tag
            ciphertext = f.read() # Read the remaining ciphertext
        
        decrypted_content = decrypt_data(nonce, ciphertext, tag)
        if decrypted_content:
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, decrypted_content)
        
            root.title(f"Notepad - {file_path}")
            current_file = file_path
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open and decrypt file: {e}")

def save_file():
    """Saves the content of the text widget to a file using AES encryption."""
    global current_file
    if current_file:
        file_path = current_file
    else:
        file_path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("AES Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if not file_path:
            return
    
    try:
        content_bytes = text_area.get(1.0, tk.END).encode('utf-8')
        nonce, ciphertext, tag = encrypt_data(content_bytes)

        # Write the nonce, tag, and ciphertext to the file
        with open(file_path, "wb") as f:
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)
            
        root.title(f"Notepad - {file_path}")
        current_file = file_path
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save and encrypt file: {e}")

# Create the main application window
root = tk.Tk()
root.title("Notepad - Untitled (AES Encrypted)")
root.geometry("800x600")

# Create the text area
text_area = tk.Text(root, wrap="word", undo=True)
text_area.pack(expand=True, fill="both")

# Create the menu bar
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

# Create the "File" menu
file_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="New", command=new_file)
file_menu.add_command(label="Open", command=open_file)
file_menu.add_command(label="Save", command=save_file)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)

# Run the main event loop
root.mainloop()