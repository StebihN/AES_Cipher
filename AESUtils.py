class AESUtils:
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
