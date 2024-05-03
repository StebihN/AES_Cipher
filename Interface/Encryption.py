import tkinter as tk


class Encryption(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        self.decryption_label = tk.Label(self, text="Cipher", font=("Helvetica", 16))
        self.decryption_label.pack()

        self.encrypt_button = tk.Button(self, height=2, width=20, text="Encrypt",
                                        command=lambda: self.parent.cipher.encrypt(parent.file,
                                                                                   parent.selected_mode.get(),
                                                                                   parent.file_format,
                                                                                   self.update_speed))
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(self, height=2, width=20, text="Decrypt",
                                        command=lambda: self.parent.cipher.decrypt(parent.file,
                                                                                   parent.selected_mode.get(),
                                                                                   parent.file_format,
                                                                                   self.update_speed))
        self.decrypt_button.pack(pady=10)

        self.speed_label = tk.Label(self, text="Speed", font=("Helvetica", 16))
        self.speed_label.pack()

        self.speed_text = tk.Text(self, height=2, width=20, font=("Helvetica", 12))
        self.speed_text.pack(pady=10)

    def update_speed(self, message):
        self.speed_text.delete("1.0", tk.END)
        self.speed_text.insert('1.0', str(message) + "B/s")
