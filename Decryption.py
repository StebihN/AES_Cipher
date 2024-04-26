import tkinter as tk


class DecryptionPage(tk.Frame):
    def __init__(self, parent, selected_mode, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)

        self.selected_mode = selected_mode

        self.decryption_label = tk.Label(self, text="Decryption", font=("Helvetica", 16))
        self.decryption_label.pack()

        self.load_key_button = tk.Button(self, height=2, width=20, text="Load Key")
        self.load_key_button.pack(pady=10)

        self.decrypt_button = tk.Button(self, height=2, width=20, text="Decrypt")
        self.decrypt_button.pack(pady=10)

        self.speed_label = tk.Label(self, text="Speed", font=("Helvetica", 16))
        self.speed_label.pack()

        self.speed_text = tk.Text(self, height=2, width=20, font=("Helvetica", 12))
        self.speed_text.pack(pady=10)

