from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import secrets
import time
import tkinter as tk
import tkinter.filedialog


class EncryptionApp(tk.Tk):
    def __init__(self, *args, **kwargs):
        self.iv = secrets.token_bytes(16)
        self.message = b''
        self.key = b''

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
            frame = F(container, self, self.selected_mode)
            self.frames[F] = frame
            frame.grid(row=1, column=0, sticky="nsew")

        self.menu = MenuRow(container, self)
        self.menu.grid(row=0, column=0, sticky="nsew")

        self.show_frame(HomePage)

    def open_file(self):
        self.message = FileIOUtils.open_file()

    def generate_key(self):
        self.key = FileIOUtils.generate_key()

    def open_key(self):
        self.key = FileIOUtils.open_key()

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

    @staticmethod
    def update_speed(frame, speed):
        frame.speed_text.delete(1.0, tk.END)
        frame.speed_text.insert(tk.END, f'{speed} MB/s')


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
    def __init__(self, parent, controller, selected_mode):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        encryption_label = tk.Label(self, text="Home Page", font=("Helvetica", 16))
        encryption_label.pack()

        open_button = tk.Button(self, height=2, width=20, text="Open File", command=lambda: controller.open_file())
        open_button.pack(pady=10)

        possible_modes = ["ECB", "CBC", "CTR", "CCM"]

        option_menu = tk.OptionMenu(self, selected_mode, *possible_modes)
        option_menu.config(height=2, width=20)
        option_menu.pack(pady=10)


class EncryptionPage(tk.Frame):
    def __init__(self, parent, controller, selected_mode):
        tk.Frame.__init__(self, parent)

        encryption_label = tk.Label(self, text="Encryption", font=("Helvetica", 16))
        encryption_label.pack()

        generate_key_button = tk.Button(self,
                                        height=2,
                                        width=20,
                                        text="Generate key",
                                        command=lambda: controller.generate_key())
        generate_key_button.pack(pady=10)

        encrypt_button = tk.Button(
            self,
            height=2,
            width=20,
            text="Encrypt",
            command=lambda: self.encrypt(controller.key,
                                         controller.message,
                                         selected_mode.get(),
                                         controller.iv,
                                         controller.update_speed))
        encrypt_button.pack(pady=10)

        speed_label = tk.Label(self, text="Speed", font=("Helvetica", 16))
        speed_label.pack()

        self.speed_text = tk.Text(self, height=2, width=20, font=("Helvetica", 12))
        self.speed_text.pack(pady=10)

    def encrypt(self, used_key, plaintext, mode, used_iv=None, callback=None):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(used_key), modes.ECB(), backend=backend)
        t1 = time.time()

        if mode == "ECB":
            ciphertext = Encryption.encrypt_ecb(cipher, plaintext)
        elif mode == "CBC":
            ciphertext = Encryption.encrypt_cbc(cipher, plaintext, used_iv)
        elif mode == "CTR":
            ciphertext = Encryption.encrypt_ctr(cipher, plaintext, used_iv)
        elif mode == "CCM":
            ciphertext = Encryption.encrypt_ccm(cipher, plaintext, used_iv)
        else:
            raise ValueError("Invalid encryption mode")

        t2 = time.time()
        speed = SpeedUtils.calculate_speed(plaintext, t1, t2)
        if callback:
            callback(self, speed)

        FileIOUtils.save_file(b64encode(ciphertext))


class DecryptionPage(tk.Frame):
    def __init__(self, parent, controller, selected_mode):
        tk.Frame.__init__(self, parent)

        decryption_label = tk.Label(self, text="Decryption", font=("Helvetica", 16))
        decryption_label.pack()

        load_key_button = tk.Button(self,
                                    height=2,
                                    width=20,
                                    text="Load Key",
                                    command=lambda: controller.open_key())
        load_key_button.pack(pady=10)

        decrypt_button = tk.Button(
            self,
            height=2,
            width=20,
            text="Decrypt",
            command=lambda: self.decrypt(controller.key,
                                     controller.message,
                                     selected_mode.get(),
                                     controller.iv,
                                     controller.update_speed))
        decrypt_button.pack(pady=10)

        speed_label = tk.Label(self, text="Speed", font=("Helvetica", 16))
        speed_label.pack()

        self.speed_text = tk.Text(self, height=2, width=20, font=("Helvetica", 12))
        self.speed_text.pack(pady=10)

    def decrypt(self, used_key, ciphertext, mode, used_iv=None, callback=None):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(used_key), modes.ECB(), backend=backend)
        ciphertext = b64decode(ciphertext)
        t1 = time.time()

        if mode == "ECB":
            plaintext = Encryption.decrypt_ecb(cipher, ciphertext)
        elif mode == "CBC":
            plaintext = Encryption.decrypt_cbc(cipher, ciphertext, used_iv)
        elif mode == "CTR":
            plaintext = Encryption.decrypt_ctr(cipher, ciphertext, used_iv)
        elif mode == "CCM":
            plaintext = Encryption.decrypt_ccm(cipher, ciphertext, used_iv)
        else:
            raise ValueError("Invalid decryption mode")

        t2 = time.time()
        speed = SpeedUtils.calculate_speed(plaintext, t1, t2)
        if callback:
            callback(self, speed)

        FileIOUtils.save_file(plaintext)


class FileIOUtils:
    @staticmethod
    def open_file():
        path = tkinter.filedialog.askopenfilename(filetypes=[('all files', '*.*')])
        with open(path, "rb") as file:
            return file.read()

    @staticmethod
    def save_file(used_message):
        file_path = tkinter.filedialog.asksaveasfilename(filetypes=[("All Files", "*.*")])
        with open(file_path, 'xb') as file:
            file.write(used_message)

    @staticmethod
    def generate_key():
        key = secrets.token_bytes(32)
        FileIOUtils.save_key(key)
        return key

    @staticmethod
    def save_key(generated_key):
        file_path = tkinter.filedialog.asksaveasfilename(defaultextension=".txt")
        with open(file_path, 'xb') as file:
            file.write(generated_key)

    @staticmethod
    def open_key():
        path = tkinter.filedialog.askopenfilename(filetypes=[('Key files', '*.*')])
        with open(path, "rb") as file:
            return file.read()


class SpeedUtils:
    @staticmethod
    def calculate_speed(file, t1, t2):
        file_size = len(file) / (1024 * 1024)
        seconds = t2 - t1
        return round(file_size / seconds, 2)


class EncryptionUtils:
    @staticmethod
    def add_pkcs7_padding(plaintext, block_size=16):
        padding_size = block_size - len(plaintext) % block_size
        padded_text = plaintext + bytes([padding_size] * padding_size)
        return padded_text

    @staticmethod
    def remove_pkcs7_padding(padded_text):
        padding_size = padded_text[-1]
        if padding_size > len(padded_text) or any(byte != padding_size for byte in padded_text[-padding_size:]):
            raise ValueError("Invalid padding")
        return padded_text

    @staticmethod
    def split_text_to_blocks(text, block_size=16):
        blocks = [text[i:i + block_size] for i in range(0, len(text), block_size)]
        return blocks

    @staticmethod
    def calculate_mac(cipher, mac, split_plaintext):
        for block in split_plaintext:
            encryptor = cipher.encryptor()
            working_block = encryptor.update(mac) + encryptor.finalize()
            mac = bytes(x ^ y for x, y in zip(block, working_block))
        return mac


class Encryption:
    @staticmethod
    def encrypt_ecb(cipher, plaintext):
        plaintext = EncryptionUtils.add_pkcs7_padding(plaintext)
        ciphertext = b''

        for block in EncryptionUtils.split_text_to_blocks(plaintext):
            encryptor = cipher.encryptor()
            split_ciphertext = encryptor.update(block) + encryptor.finalize()
            ciphertext += split_ciphertext

        return ciphertext

    @staticmethod
    def decrypt_ecb(cipher, ciphertext):
        plaintext = b''

        for block in EncryptionUtils.split_text_to_blocks(ciphertext):
            decryptor = cipher.decryptor()
            split_plaintext = decryptor.update(block) + decryptor.finalize()
            plaintext += split_plaintext

        plaintext = EncryptionUtils.remove_pkcs7_padding(plaintext)
        return plaintext

    @staticmethod
    def encrypt_cbc(cipher, plaintext, used_iv):
        plaintext = EncryptionUtils.add_pkcs7_padding(plaintext)
        ciphertext = b""
        previous_block = used_iv

        for block in EncryptionUtils.split_text_to_blocks(plaintext):
            encryptor = cipher.encryptor()
            working_block = bytes(x ^ y for x, y in zip(block, previous_block))
            encrypted_block = encryptor.update(working_block) + encryptor.finalize()
            ciphertext += encrypted_block
            previous_block = encrypted_block

        return ciphertext

    @staticmethod
    def decrypt_cbc(cipher, ciphertext, used_iv):
        plaintext = b""
        previous_block = used_iv

        for block in EncryptionUtils.split_text_to_blocks(ciphertext):
            decryptor = cipher.decryptor()
            working_block = decryptor.update(block) + decryptor.finalize()
            decrypted_block = bytes(x ^ y for x, y in zip(working_block, previous_block))
            plaintext += decrypted_block
            previous_block = block

        plaintext = EncryptionUtils.remove_pkcs7_padding(plaintext)
        return plaintext

    @staticmethod
    def ctr_mode(cipher, returned_text, counter, given_text):
        for block in EncryptionUtils.split_text_to_blocks(given_text):
            counter_bytes = counter.to_bytes(16, byteorder='big')
            encryptor = cipher.encryptor()
            key_stream_block = encryptor.update(counter_bytes) + encryptor.finalize()
            encrypted_block = bytes(x ^ y for x, y in zip(block, key_stream_block))
            returned_text += encrypted_block
            counter += 1
        return returned_text

    @staticmethod
    def encrypt_ctr(cipher, plaintext, used_iv):
        plaintext = EncryptionUtils.add_pkcs7_padding(plaintext)
        ciphertext = b""
        counter = int.from_bytes(used_iv, byteorder='big')

        ciphertext = Encryption.ctr_mode(cipher, ciphertext, counter, plaintext)

        return ciphertext

    @staticmethod
    def decrypt_ctr(cipher, ciphertext, used_iv):
        plaintext = b""
        counter = int.from_bytes(used_iv, byteorder='big')

        plaintext = Encryption.ctr_mode(cipher, plaintext, counter, ciphertext)
        plaintext = EncryptionUtils.remove_pkcs7_padding(plaintext)

        return plaintext

    @staticmethod
    def encrypt_ccm(cipher, plaintext, used_iv):
        plaintext = EncryptionUtils.add_pkcs7_padding(plaintext)
        counter = int.from_bytes(used_iv, byteorder='big')
        mac = used_iv
        ciphertext = b""

        mac = EncryptionUtils.calculate_mac(cipher, mac, EncryptionUtils.split_text_to_blocks(plaintext))
        ciphertext = Encryption.ctr_mode(cipher, ciphertext, counter, plaintext)
        ciphertext += mac

        return ciphertext

    @staticmethod
    def decrypt_ccm(cipher, ciphertext, used_iv):
        counter = int.from_bytes(used_iv, byteorder='big')
        mac = used_iv
        calculated_mac = ciphertext[-16:]
        ciphertext = ciphertext[:-16]
        plaintext = b""

        plaintext = Encryption.ctr_mode(cipher, plaintext, counter, ciphertext)
        mac = EncryptionUtils.calculate_mac(cipher, mac, EncryptionUtils.split_text_to_blocks(plaintext))
        plaintext = EncryptionUtils.remove_pkcs7_padding(plaintext)

        if calculated_mac == mac:
            return plaintext
        else:
            raise ValueError("Mac doesn't match")


if __name__ == "__main__":
    app = EncryptionApp()
    app.mainloop()
