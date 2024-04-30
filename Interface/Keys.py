import tkinter as tk


class KeysPage(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)

        self.heading = tk.Label(self, text="Keys", font=("Helvetica", 16))
        self.heading.pack()

        self.save_key_button = tk.Button(self, height=2, width=20, text="Save key",
                                             command=lambda: parent.cipher.save_key())
        self.save_key_button.pack(pady=10)

        self.load_key_button = tk.Button(self, height=2, width=20, text="Load Key",
                                         command=lambda: parent.cipher.open_key())
        self.load_key_button.pack(pady=10)
