import tkinter as tk

from Decryption import DecryptionPage
from Encryption import EncryptionPage
from HomePage import HomePage


class Navbar(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        self.home_button = tk.Button(self, text="Home", command=lambda: self.parent.switch_frame(HomePage))
        self.home_button.grid(row=0, column=0, padx=5)

        self.encryption_button = tk.Button(self, text="Encryption", command=lambda: self.parent.switch_frame(EncryptionPage))
        self.encryption_button.grid(row=0, column=1, padx=5)

        self.decryption_button = tk.Button(self, text="Decryption", command=lambda: self.parent.switch_frame(DecryptionPage))
        self.decryption_button.grid(row=0, column=2, padx=5)
