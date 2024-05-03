import tkinter as tk


class Ivs(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        self.heading = tk.Label(self, text="Ivs", font=("Helvetica", 16))
        self.heading.pack()

        self.load_iv_button = tk.Button(self, height=2, width=20, text="Load IV",
                                        command=lambda: self.parent.cipher.open_iv())
        self.load_iv_button.pack(pady=10)
