import tkinter as tk


class EncryptionPage(tk.Frame):
    def __init__(self, parent, selected_mode, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)

        self.selected_mode = selected_mode

        self.encryption_label = tk.Label(self, text="Encryption", font=("Helvetica", 16))
        self.encryption_label.pack()

        self.generate_key_button = tk.Button(self, height=2, width=20, text="Generate key")
        self.generate_key_button.pack(pady=10)

        self.encrypt_button = tk.Button(self, height=2, width=20, text="Encrypt")
        self.encrypt_button.pack(pady=10)

        self.speed_label = tk.Label(self, text="Speed", font=("Helvetica", 16))
        self.speed_label.pack()

        self.speed_text = tk.Text(self, height=2, width=20, font=("Helvetica", 12))
        self.speed_text.pack(pady=10)
