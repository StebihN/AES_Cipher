from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import secrets
import random
import os
import tkinter as tk
import tkinter.filedialog

iv = secrets.token_bytes(16)
message = b''
key = b''
extension = ""

def add_pkcs7_padding(plaintext, block_size=16):
    padding_size = block_size - len(plaintext) % block_size
    padded_text = plaintext + bytes([padding_size] * padding_size)
    return padded_text


def remove_pkcs7_padding(padded_text):
    padding_size = padded_text[-1]
    if padding_size > len(padded_text) or any(byte != padding_size for byte in padded_text[-padding_size:]):
        raise ValueError("Invalid padding")
    return padded_text[:-padding_size]


def split_text_to_blocks(text, block_size=16):
    blocks = [text[i:i + block_size] for i in range(0, len(text), block_size)]
    return blocks


def aes_encrypt_ecb(key, plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

    plaintext = add_pkcs7_padding(plaintext)
    split_plaintext = split_text_to_blocks(plaintext)
    ciphertext = b""

    for block in split_plaintext:
        encryptor = cipher.encryptor()
        split_ciphertext = encryptor.update(block) + encryptor.finalize()
        ciphertext = ciphertext + split_ciphertext

    savefile(b64encode(ciphertext))


def aes_decrypt_ecb(key, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    ciphertext = b64decode(ciphertext)

    split_ciphertext = split_text_to_blocks(ciphertext)
    plaintext = b""

    for block in split_ciphertext:
        decryptor = cipher.decryptor()
        split_plaintext = decryptor.update(block) + decryptor.finalize()
        plaintext = plaintext + split_plaintext

    plaintext = remove_pkcs7_padding(plaintext)

    savefile(plaintext)


def aes_encrypt_cbc(key, plaintext):
    temporary_block = iv

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

    plaintext = add_pkcs7_padding(plaintext)
    split_plaintext = split_text_to_blocks(plaintext)
    ciphertext = b""

    for block in split_plaintext:
        encryptor = cipher.encryptor()

        working_block = bytes(x ^ y for x, y in zip(block, temporary_block))
        split_ciphertext = encryptor.update(working_block) + encryptor.finalize()

        temporary_block = split_ciphertext

        ciphertext = ciphertext + split_ciphertext

    savefile(b64encode(ciphertext))



def aes_decrypt_cbc(key, ciphertext):
    temporary_block = iv

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    ciphertext = b64decode(ciphertext)

    split_ciphertext = split_text_to_blocks(ciphertext)
    plaintext = b""

    for block in split_ciphertext:
        decryptor = cipher.decryptor()
        split_plaintext = decryptor.update(block) + decryptor.finalize()
        working_block = bytes(x ^ y for x, y in zip(split_plaintext, temporary_block))
        temporary_block = block
        plaintext += working_block

    plaintext = remove_pkcs7_padding(plaintext)

    savefile(plaintext)



def aes_encrypt_ctr(key, plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

    # Initialize counter
    counter = int.from_bytes(iv, byteorder='big')

    plaintext = add_pkcs7_padding(plaintext)
    split_plaintext = split_text_to_blocks(plaintext)
    ciphertext = b""

    for block in split_plaintext:
        counter_bytes = counter.to_bytes(16, byteorder='big')

        encryptor = cipher.encryptor()
        keystream_block = encryptor.update(counter_bytes) + encryptor.finalize()

        encrypted_block = bytes(x ^ y for x, y in zip(block, keystream_block))

        counter += 1

        ciphertext += encrypted_block

    savefile(b64encode(ciphertext))


def aes_decrypt_ctr(key, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

    counter = int.from_bytes(iv, byteorder='big')

    ciphertext = b64decode(ciphertext)
    split_ciphertext = split_text_to_blocks(ciphertext)
    plaintext = b""

    for block in split_ciphertext:
        counter_bytes = counter.to_bytes(16, byteorder='big')
        encryptor = cipher.encryptor()
        keystream_block = encryptor.update(counter_bytes) + encryptor.finalize()

        decrypted_block = bytes(x ^ y for x, y in zip(block, keystream_block))

        counter += 1

        plaintext += decrypted_block

    plaintext = remove_pkcs7_padding(plaintext)

    savefile(plaintext)

def aes_encrypt_ccm(key, plaintext):
    mac = iv
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

    counter = int.from_bytes(iv, byteorder='big')

    plaintext = add_pkcs7_padding(plaintext)
    split_plaintext = split_text_to_blocks(plaintext)
    ciphertext = b""

    for block in split_plaintext:
        encryptor = cipher.encryptor()

        working_block = encryptor.update(mac) + encryptor.finalize()
        mac = bytes(x ^ y for x, y in zip(block, working_block))


    for block in split_plaintext:
        counter_bytes = counter.to_bytes(16, byteorder='big')

        encryptor = cipher.encryptor()
        keystream_block = encryptor.update(counter_bytes) + encryptor.finalize()

        encrypted_block = bytes(x ^ y for x, y in zip(block, keystream_block))

        counter += 1

        ciphertext += encrypted_block

    ciphertext += mac
    savefile(b64encode(ciphertext))

def aes_decrypt_ccm(key, ciphertext):
    mac = iv
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

    counter = int.from_bytes(iv, byteorder='big')

    ciphertext = b64decode(ciphertext)
    recieved_mac = ciphertext[-16:]
    ciphertext = ciphertext[:-16]
    split_ciphertext = split_text_to_blocks(ciphertext)
    plaintext = b""


    for block in split_ciphertext:
        counter_bytes = counter.to_bytes(16, byteorder='big')

        encryptor = cipher.encryptor()
        keystream_block = encryptor.update(counter_bytes) + encryptor.finalize()

        decrypted_block = bytes(x ^ y for x, y in zip(block, keystream_block))

        counter += 1

        plaintext += decrypted_block

    split_plaintext = split_text_to_blocks(plaintext)

    for block in split_plaintext:
        encryptor = cipher.encryptor()

        working_block = encryptor.update(mac) + encryptor.finalize()
        mac = bytes(x ^ y for x, y in zip(block, working_block))

    plaintext = remove_pkcs7_padding(plaintext)

    if recieved_mac == mac:
        savefile(plaintext)
    else:
        print("mac doesnt match")

def encrypt(selected_mode):
    if selected_mode.get() == "ECB":
        aes_encrypt_ecb(key, message)
    elif selected_mode.get() == "CBC":
        aes_encrypt_cbc(key, message)
    elif selected_mode.get() == "CTR":
        aes_encrypt_ctr(key, message)
    elif selected_mode.get() == "CCM":
        aes_encrypt_ccm(key, message)


def decrypt(selected_mode):
    if selected_mode.get() == "ECB":
        aes_decrypt_ecb(key, message)
    elif selected_mode.get() == "CBC":
        aes_decrypt_cbc(key, message)
    elif selected_mode.get() == "CTR":
        aes_decrypt_ctr(key, message)
    elif selected_mode.get() == "CCM":
        aes_decrypt_ccm(key, message)


def get_file_type(file_path):
    _, file_extension = os.path.splitext(file_path)
    return file_extension


def openfile():
    global message
    global extension
    path = tkinter.filedialog.askopenfilename(filetypes=[('all files', '*.*')])
    extension = get_file_type(path)
    with open(path, "rb") as file:
        message = file.read()


def savefile(used_message):
    file = open("file" + str(random.randint(1, 100)) + extension, "xb")
    file.write(used_message)
    file.close()


def generate_key():
    global key
    key = secrets.token_bytes(32)
    save_key(key)


def save_key(generated_key):
    file = open("key" + str(random.randint(1, 100)) + ".txt", "xb")
    file.write(generated_key)
    file.close()


def openkey():
    global key
    path = tkinter.filedialog.askopenfilename(filetypes=[('Key files', '*.*')])
    with open(path, "rb") as file:
        key = file.read()


class EncryptionApp(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title('Exercise_2')
        self.geometry("260x200")

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (HomePage, EncryptionPage, DecryptionPage, SpeedPage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=1, column=0, sticky="nsew")

        self.menu = MenuRow(container, self)
        self.menu.grid(row=0, column=0, sticky="nsew")

        self.show_frame(HomePage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()


class MenuRow(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        home_button = tk.Button(self, text="Home", command=lambda: controller.show_frame(HomePage))
        home_button.grid(row=0, column=0, padx=5)

        encryption_button = tk.Button(self, text="Encryption", command=lambda: controller.show_frame(EncryptionPage))
        encryption_button.grid(row=0, column=1, padx=5)

        decryption_button = tk.Button(self, text="Decryption", command=lambda: controller.show_frame(DecryptionPage))
        decryption_button.grid(row=0, column=2, padx=5)

        speed_button = tk.Button(self, text="Speed", command=lambda: controller.show_frame(SpeedPage))
        speed_button.grid(row=0, column=3, padx=5)


class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        encryption_label = tk.Label(self, text="Home Page", font=("Helvetica", 16))
        encryption_label.pack()

        open_button = tk.Button(self, height=2, width=20, text="Open File")
        open_button.pack(pady=10)

        selected_mode = tk.StringVar(self)
        selected_mode.set("ECB")
        possible_modes = ["ECB", "CBC", "CTR", "CCM"]

        option_menu = tk.OptionMenu(self, selected_mode, *possible_modes)
        option_menu.config(height=2, width=20)
        option_menu.pack(pady=10)


class EncryptionPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        encryption_label = tk.Label(self, text="Encryption", font=("Helvetica", 16))
        encryption_label.pack()

        generate_key_button = tk.Button(self, height=2, width=20, text="Generate key")
        generate_key_button.pack(pady=10)

        encrypt_button = tk.Button(self, height=2, width=20, text="Encrypt")
        encrypt_button.pack(pady=10)


class DecryptionPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        decryption_label = tk.Label(self, text="Decryption", font=("Helvetica", 16))
        decryption_label.pack()

        load_key_button = tk.Button(self, height=2, width=20, text="Load Key")
        load_key_button.pack(pady=10)

        decrypt_button = tk.Button(self, height=2, width=20, text="Decrypt")
        decrypt_button.pack(pady=10)


class SpeedPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

        speed_label = tk.Label(self, text="Speed", font=("Helvetica", 16))
        speed_label.pack()

        speed_text = tk.Text(self, height=2, width=20, font=("Helvetica", 12))
        speed_text.pack(pady=10)


if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()
