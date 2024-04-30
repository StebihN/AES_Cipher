import tkinter as tk

from Interface.Encryption import Encryption
from Interface.Ivs import Ivs
from Interface.Keys import KeysPage
from Interface.HomePage import HomePage


class Navbar(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        self.home_button = tk.Button(self, text="Home", command=lambda: self.parent.switch_frame(HomePage))
        self.home_button.grid(row=0, column=0, padx=5)

        self.keys_button = tk.Button(self, text="Keys", command=lambda: self.parent.switch_frame(KeysPage))
        self.keys_button.grid(row=0, column=1, padx=5)

        self.ivs_button = tk.Button(self, text="IVs", command=lambda: self.parent.switch_frame(Ivs))
        self.ivs_button.grid(row=0, column=2, padx=5)

        self.encryption_button = tk.Button(self, text="Encryption",
                                           command=lambda: self.parent.switch_frame(Encryption))
        self.encryption_button.grid(row=0, column=3, padx=5)
