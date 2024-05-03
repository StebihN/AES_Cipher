import tkinter as tk


class HomePage(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent

        self.encryption_label = tk.Label(self, text="Home Page", font=("Helvetica", 16))
        self.encryption_label.pack()

        self.open_button = tk.Button(self, height=2, width=20, text="Open File",
                                     command=lambda: self.parent.open_file())
        self.open_button.pack(pady=10)

        self.possible_modes = ["ECB", "CBC", "CTR", "CCM"]
        self.option_menu = tk.OptionMenu(self, self.parent.selected_mode, *self.possible_modes)
        self.option_menu.config(height=2, width=20)
        self.option_menu.pack(pady=10)
