from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import secrets
import time

from AESUtils import AESUtils
from Utils import Utils


class AES:
    def __init__(self):
        self.backend = default_backend()
        self.iv = secrets.token_bytes(16)
        self.key = b''

        self.cipher = None

    def generate_key(self):
        self.key = secrets.token_bytes(32)
        self.cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)
        Utils.save_file(self.key, ".txt")

    def open_key(self):
        f_types = [("Text Files", "*.txt")]
        self.key = Utils.open_file(f_types)
        self.cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)

    def encrypt(self, plaintext, mode, file_format, callback=None):
        t1 = time.time()

        if mode == "ECB":
            ciphertext = b64encode(self.encrypt_ecb(plaintext))
        elif mode == "CBC":
            ciphertext = b64encode(self.encrypt_cbc(plaintext))
        elif mode == "CTR":
            ciphertext = b64encode(self.encrypt_ctr(plaintext))
        elif mode == "CCM":
            ciphertext = b64encode(self.encrypt_ccm(plaintext))
        else:
            raise ValueError("Invalid encryption mode")

        t2 = time.time()

        speed = Utils.calculate_speed(plaintext, t1, t2)
        if callback:
            callback(speed)

        Utils.save_file(ciphertext, file_format)

    def decrypt(self, ciphertext, mode, file_format, callback=None):
        t1 = time.time()

        if mode == "ECB":
            plaintext = self.decrypt_ecb(b64decode(ciphertext))
        elif mode == "CBC":
            plaintext = self.decrypt_cbc(b64decode(ciphertext))
        elif mode == "CTR":
            plaintext = self.decrypt_ctr(b64decode(ciphertext))
        elif mode == "CCM":
            plaintext = self.decrypt_ccm(b64decode(ciphertext))
        else:
            raise ValueError("Invalid decryption mode")

        t2 = time.time()
        
        speed = Utils.calculate_speed(plaintext, t1, t2)
        if callback:
            callback(speed)

        Utils.save_file(plaintext, file_format)

    def encrypt_ecb(self, plaintext):
        plaintext = AESUtils.add_pkcs7_padding(plaintext)
        ciphertext = b''

        for block in AESUtils.split_text_to_blocks(plaintext):
            encryptor = self.cipher.encryptor()
            split_ciphertext = encryptor.update(block) + encryptor.finalize()
            ciphertext += split_ciphertext

        return ciphertext

    def decrypt_ecb(self, ciphertext):
        plaintext = b''

        for block in AESUtils.split_text_to_blocks(ciphertext):
            decryptor = self.cipher.decryptor()
            split_plaintext = decryptor.update(block) + decryptor.finalize()
            plaintext += split_plaintext

        plaintext = AESUtils.remove_pkcs7_padding(plaintext)
        return plaintext

    def encrypt_cbc(self, plaintext):
        plaintext = AESUtils.add_pkcs7_padding(plaintext)
        ciphertext = b""
        previous_block = self.iv

        for block in AESUtils.split_text_to_blocks(plaintext):
            encryptor = self.cipher.encryptor()
            working_block = bytes(x ^ y for x, y in zip(block, previous_block))
            encrypted_block = encryptor.update(working_block) + encryptor.finalize()
            ciphertext += encrypted_block
            previous_block = encrypted_block

        return ciphertext

    def decrypt_cbc(self, ciphertext):
        plaintext = b""
        previous_block = self.iv

        for block in AESUtils.split_text_to_blocks(ciphertext):
            decryptor = self.cipher.decryptor()
            working_block = decryptor.update(block) + decryptor.finalize()
            decrypted_block = bytes(x ^ y for x, y in zip(working_block, previous_block))
            plaintext += decrypted_block
            previous_block = block

        plaintext = AESUtils.remove_pkcs7_padding(plaintext)
        return plaintext

    def ctr_mode(self, returned_text, counter, given_text):
        for block in AESUtils.split_text_to_blocks(given_text):
            counter_bytes = counter.to_bytes(16, byteorder='big')
            encryptor = self.cipher.encryptor()
            key_stream_block = encryptor.update(counter_bytes) + encryptor.finalize()
            encrypted_block = bytes(x ^ y for x, y in zip(block, key_stream_block))
            returned_text += encrypted_block
            counter += 1
        return returned_text

    def encrypt_ctr(self, plaintext):
        plaintext = AESUtils.add_pkcs7_padding(plaintext)
        ciphertext = b""
        counter = int.from_bytes(self.iv, byteorder='big')

        ciphertext = self.ctr_mode(ciphertext, counter, plaintext)

        return ciphertext

    def decrypt_ctr(self, ciphertext):
        plaintext = b""
        counter = int.from_bytes(self.iv, byteorder='big')

        plaintext = self.ctr_mode(plaintext, counter, ciphertext)
        plaintext = AESUtils.remove_pkcs7_padding(plaintext)

        return plaintext

    def encrypt_ccm(self, plaintext):
        plaintext = AESUtils.add_pkcs7_padding(plaintext)
        counter = int.from_bytes(self.iv, byteorder='big')
        mac = self.iv
        ciphertext = b""

        mac = AESUtils.calculate_mac(self.cipher, mac, AESUtils.split_text_to_blocks(plaintext))
        ciphertext = self.ctr_mode(ciphertext, counter, plaintext)
        ciphertext += mac

        return ciphertext

    def decrypt_ccm(self, ciphertext):
        counter = int.from_bytes(self.iv, byteorder='big')
        mac = self.iv
        calculated_mac = ciphertext[-16:]
        ciphertext = ciphertext[:-16]
        plaintext = b""

        plaintext = self.ctr_mode(plaintext, counter, ciphertext)
        mac = AESUtils.calculate_mac(self.cipher, mac, AESUtils.split_text_to_blocks(plaintext))
        plaintext = AESUtils.remove_pkcs7_padding(plaintext)

        if calculated_mac == mac:
            return plaintext
        else:
            raise ValueError("Mac doesn't match")
