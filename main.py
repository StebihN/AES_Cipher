from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import secrets
import random
import os
from tkinter import *
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
        # Convert the counter to bytes
        counter_bytes = counter.to_bytes(16, byteorder='big')

        # Encrypt the counter using the key
        encryptor = cipher.encryptor()
        keystream_block = encryptor.update(counter_bytes) + encryptor.finalize()

        # XOR the keystream with the plaintext block
        encrypted_block = bytes(x ^ y for x, y in zip(block, keystream_block))

        # Increment the counter for the next block
        counter += 1

        ciphertext += encrypted_block

    savefile(b64encode(ciphertext))


def aes_decrypt_ctr(key, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

    # Initialize counter
    counter = int.from_bytes(iv, byteorder='big')

    ciphertext = b64decode(ciphertext)
    split_ciphertext = split_text_to_blocks(ciphertext)
    plaintext = b""

    for block in split_ciphertext:
        # Convert the counter to bytes
        counter_bytes = counter.to_bytes(16, byteorder='big')

        # Encrypt the counter using the key
        encryptor = cipher.encryptor()
        keystream_block = encryptor.update(counter_bytes) + encryptor.finalize()

        # XOR the keystream with the ciphertext block
        decrypted_block = bytes(x ^ y for x, y in zip(block, keystream_block))

        # Increment the counter for the next block
        counter += 1

        plaintext += decrypted_block

    plaintext = remove_pkcs7_padding(plaintext)

    savefile(plaintext)



def encrypt(selected_mode):
    if selected_mode.get() == "ECB":
        aes_encrypt_ecb(key, message)
    elif selected_mode.get() == "CBC":
        aes_encrypt_cbc(key, message)
    elif selected_mode.get() == "CTR":
        aes_encrypt_ctr(key, message)
    elif selected_mode.get() == "CCM":
        print("not yet implemented")


def decrypt(selected_mode):
    if selected_mode.get() == "ECB":
        aes_decrypt_ecb(key, message)
    elif selected_mode.get() == "CBC":
        aes_decrypt_cbc(key, message)
    elif selected_mode.get() == "CTR":
        aes_decrypt_ctr(key, message)
    elif selected_mode.get() == "CCM":
        print("not yet implemented")


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


master = Tk()
master.title('Exercise_2')
master.geometry("240x440+10+20")

openButton = Button(master, height=2, width=20, text="Open File", command=lambda: openfile())
openButton.pack(pady=10)

selected_mode = StringVar(master)
selected_mode.set("ECB")

possible_modes = ["ECB", "CBC", "CTR", "CCM"]

option_menu = OptionMenu(master, selected_mode, *possible_modes)
option_menu.pack(pady=10)

headingOneLabel = Label(master, text="Encryption", font=("Helvetica", 16))
headingOneLabel.pack()

generateButton = Button(master, height=2, width=20, text="Generate key", command=lambda: generate_key())
generateButton.pack(pady=10)


encryptButton = Button(master, height=2, width=20, text="Encrypt", command=lambda: encrypt(selected_mode))
encryptButton.pack(pady=10)

headingTwoLabel = Label(master, text="Decryption", font=("Helvetica", 16))
headingTwoLabel.pack()

openButton = Button(master, height=2, width=20, text="Load Key", command=lambda: openkey())
openButton.pack(pady=10)

decryptButton = Button(master, height=2, width=20, text="Decrypt", command=lambda: decrypt(selected_mode))
decryptButton.pack(pady=10)

headingThreeLabel = Label(master, text="Speed", font=("Helvetica", 16))
headingThreeLabel.pack()

speed = Text(master, font=("Helvetica", 12))
speed.pack(pady=10)

master.mainloop()
