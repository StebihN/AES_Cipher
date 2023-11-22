from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import secrets
import tkinter as tk
import tkinter.filedialog
import os
import time

iv = secrets.token_bytes(16)
message = b''
key = b''
extension = ""
speed_amount = ""


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


def calculate_mac(cipher, mac, split_plaintext):
    for block in split_plaintext:
        encryptor = cipher.encryptor()

        working_block = encryptor.update(mac) + encryptor.finalize()
        mac = bytes(x ^ y for x, y in zip(block, working_block))
    return mac

def calculate_speed(plaintext, t1, t2):
    global speed_amount
    size = len(plaintext) / (1024 * 1024)
    seconds = t2 - t1
    speed = round(size / seconds, 2)
    speed_amount = f'{speed} MB/s'

def encrypt(key, plaintext, mode, iv=None):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    t1 = time.time()

    if mode == "ECB":
        ciphertext = encrypt_ecb(cipher, plaintext)
    elif mode == "CBC":
        ciphertext = encrypt_cbc(cipher, plaintext, iv)
    elif mode == "CTR":
        ciphertext = encrypt_ctr(cipher, plaintext, iv)
    elif mode == "CCM":
        ciphertext = encrypt_ccm(cipher, plaintext, iv)
    else:
        raise ValueError("Invalid encryption mode")

    t2 = time.time()
    calculate_speed(plaintext, t1, t2)
    savefile(b64encode(ciphertext))


def decrypt(key, ciphertext, mode, iv=None):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    ciphertext = b64decode(ciphertext)
    t1 = time.time()

    if mode == "ECB":
        plaintext = decrypt_ecb(cipher, ciphertext)
    elif mode == "CBC":
        plaintext = decrypt_cbc(cipher, ciphertext, iv)
    elif mode == "CTR":
        plaintext = decrypt_ctr(cipher, ciphertext, iv)
    elif mode == "CCM":
        plaintext = decrypt_ccm(cipher, ciphertext, iv)
    else:
        raise ValueError("Invalid decryption mode")

    t2 = time.time()
    calculate_speed(plaintext, t1, t2)
    savefile(plaintext)


def encrypt_ecb(cipher, plaintext):
    plaintext = add_pkcs7_padding(plaintext)
    ciphertext = b''

    for block in split_text_to_blocks(plaintext):
        encryptor = cipher.encryptor()
        split_ciphertext = encryptor.update(block) + encryptor.finalize()
        ciphertext += split_ciphertext

    return ciphertext


def decrypt_ecb(cipher, ciphertext):
    plaintext = b''

    for block in split_text_to_blocks(ciphertext):
        decryptor = cipher.decryptor()
        split_plaintext = decryptor.update(block) + decryptor.finalize()
        plaintext += split_plaintext

    plaintext = remove_pkcs7_padding(plaintext)
    return plaintext


def encrypt_cbc(cipher, plaintext, iv):
    plaintext = add_pkcs7_padding(plaintext)
    ciphertext = b""
    previous_block = iv

    for block in split_text_to_blocks(plaintext):
        encryptor = cipher.encryptor()
        working_block = bytes(x ^ y for x, y in zip(block, previous_block))
        encrypted_block = encryptor.update(working_block) + encryptor.finalize()
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext


def decrypt_cbc(cipher, ciphertext, iv):
    plaintext = b""
    previous_block = iv

    for block in split_text_to_blocks(ciphertext):
        decryptor = cipher.decryptor()
        split_plaintext = decryptor.update(block) + decryptor.finalize()
        working_block = bytes(x ^ y for x, y in zip(split_plaintext, previous_block))
        previous_block = block
        plaintext += working_block

    plaintext = remove_pkcs7_padding(plaintext)
    return plaintext


def ctr_mode(cipher, ciphertext, counter, counter_bytes, plaintext):
    for block in split_text_to_blocks(plaintext):
        encryptor = cipher.encryptor()
        keystream_block = encryptor.update(counter_bytes) + encryptor.finalize()
        encrypted_block = bytes(x ^ y for x, y in zip(block, keystream_block))
        ciphertext += encrypted_block
        counter += 1
        counter_bytes = counter.to_bytes(16, byteorder='big')
    return ciphertext


def encrypt_ctr(cipher, plaintext, iv):
    plaintext = add_pkcs7_padding(plaintext)
    ciphertext = b""
    counter = int.from_bytes(iv, byteorder='big')
    counter_bytes = counter.to_bytes(16, byteorder='big')

    ciphertext = ctr_mode(cipher, ciphertext, counter, counter_bytes, plaintext)

    return ciphertext


def decrypt_ctr(cipher, ciphertext, iv):
    plaintext = b""

    counter = int.from_bytes(iv, byteorder='big')
    counter_bytes = counter.to_bytes(16, byteorder='big')

    plaintext = ctr_mode(cipher, plaintext, counter, counter_bytes, ciphertext)
    plaintext = remove_pkcs7_padding(plaintext)
    return plaintext


def encrypt_ccm(cipher, plaintext, iv):
    plaintext = add_pkcs7_padding(plaintext)
    counter = int.from_bytes(iv, byteorder='big')
    counter_bytes = counter.to_bytes(16, byteorder='big')

    mac = iv
    ciphertext = b""

    mac = calculate_mac(cipher, mac, split_text_to_blocks(plaintext))
    ciphertext = ctr_mode(cipher, ciphertext, counter, counter_bytes, plaintext)
    ciphertext += mac

    return ciphertext


def decrypt_ccm(cipher, ciphertext, iv):
    counter = int.from_bytes(iv, byteorder='big')
    counter_bytes = counter.to_bytes(16, byteorder='big')

    mac = iv
    recieved_mac = ciphertext[-16:]
    ciphertext = ciphertext[:-16]
    plaintext = b""

    plaintext = ctr_mode(cipher, plaintext, counter, counter_bytes, ciphertext)
    mac = calculate_mac(cipher, mac, split_text_to_blocks(plaintext))
    plaintext = remove_pkcs7_padding(plaintext)

    if recieved_mac == mac:
        return plaintext
    else:
        print("mac doesn't match")
        return None


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
    global extension
    file_path = tkinter.filedialog.asksaveasfilename(defaultextension=extension)
    with open(file_path, 'xb') as file:
        file.write(used_message)


def generate_key():
    global key
    key = secrets.token_bytes(32)
    save_key(key)


def save_key(generated_key):
    file_path = tkinter.filedialog.asksaveasfilename(defaultextension=".txt")
    with open(file_path, 'xb') as file:
        file.write(generated_key)


def openkey():
    global key
    path = tkinter.filedialog.askopenfilename(filetypes=[('Key files', '*.*')])
    with open(path, "rb") as file:
        key = file.read()


class EncryptionApp(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title('Exercise_2')
        self.geometry("280x280")

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.selected_mode = tk.StringVar(self)
        self.selected_mode.set("ECB")

        self.frames = {}
        for F in (HomePage, EncryptionPage, DecryptionPage):
            frame = F(container, self, self.selected_mode, speed_amount)
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


class HomePage(tk.Frame):
    def __init__(self, parent, controller, selected_mode, speed_amount):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        encryption_label = tk.Label(self, text="Home Page", font=("Helvetica", 16))
        encryption_label.pack()

        open_button = tk.Button(self, height=2, width=20, text="Open File", command=lambda: openfile())
        open_button.pack(pady=10)

        possible_modes = ["ECB", "CBC", "CTR", "CCM"]

        option_menu = tk.OptionMenu(self, selected_mode, *possible_modes)
        option_menu.config(height=2, width=20)
        option_menu.pack(pady=10)


class EncryptionPage(tk.Frame):
    def __init__(self, parent, controller, selected_mode, speed_amount):
        tk.Frame.__init__(self, parent)

        encryption_label = tk.Label(self, text="Encryption", font=("Helvetica", 16))
        encryption_label.pack()

        generate_key_button = tk.Button(self, height=2, width=20, text="Generate key", command=lambda: generate_key())
        generate_key_button.pack(pady=10)

        encrypt_button = tk.Button(self, height=2, width=20, text="Encrypt",
                                   command=lambda: [encrypt(key, message, selected_mode.get(), iv), self.update_speed()])
        encrypt_button.pack(pady=10)

        speed_label = tk.Label(self, text="Speed", font=("Helvetica", 16))
        speed_label.pack()

        self.speed_text = tk.Text(self, height=2, width=20, font=("Helvetica", 12))
        self.speed_text.pack(pady=10)

    def update_speed(self):
        self.speed_text.delete(1.0, tk.END)
        self.speed_text.insert(tk.END, speed_amount)


class DecryptionPage(tk.Frame):
    def __init__(self, parent, controller, selected_mode, speed_amount):
        tk.Frame.__init__(self, parent)

        decryption_label = tk.Label(self, text="Decryption", font=("Helvetica", 16))
        decryption_label.pack()

        load_key_button = tk.Button(self, height=2, width=20, text="Load Key", command=lambda: openkey())
        load_key_button.pack(pady=10)

        decrypt_button = tk.Button(self, height=2, width=20, text="Decrypt",
                                   command=lambda: [decrypt(key, message, selected_mode.get(), iv), self.update_speed()])
        decrypt_button.pack(pady=10)

        speed_label = tk.Label(self, text="Speed", font=("Helvetica", 16))
        speed_label.pack()

        self.speed_text = tk.Text(self, height=2, width=20, font=("Helvetica", 12))
        self.speed_text.pack(pady=10)

    def update_speed(self):
        self.speed_text.delete(1.0, tk.END)
        self.speed_text.insert(tk.END, speed_amount)



if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()