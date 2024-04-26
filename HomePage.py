import tkinter as tk


class HomePage(tk.Frame):
    def __init__(self, parent, selected_mode, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)

        self.encryption_label = tk.Label(self, text="Home Page", font=("Helvetica", 16))
        self.encryption_label.pack()

        self.open_button = tk.Button(self, height=2, width=20, text="Open File")
        self.open_button.pack(pady=10)

        self.selected_mode = selected_mode
        self.possible_modes = ["ECB", "CBC", "CTR", "CCM"]

        self.option_menu = tk.OptionMenu(self, self.selected_mode, *self.possible_modes)
        self.option_menu.config(height=2, width=20)
        self.option_menu.pack(pady=10)
