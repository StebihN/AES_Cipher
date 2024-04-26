import tkinter as tk

from Navbar import Navbar
from HomePage import HomePage


class Interface(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.selected_mode = tk.StringVar(self)
        self.selected_mode.set("ECB")

        self.navbar = Navbar(self)
        self.navbar.pack(side="top")

        self.bottom_frame = None
        self.switch_frame(HomePage)

    def switch_frame(self, frame):
        if self.bottom_frame is not None:
            self.bottom_frame.destroy()
        self.bottom_frame = frame(self, self.selected_mode)
        self.bottom_frame.pack(side="bottom")


