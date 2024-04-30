import tkinter as tk

from Navbar import Navbar
from HomePage import HomePage
from Utils import Utils


class Interface(tk.Frame):
    def __init__(self, parent, cypher, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)

        self.cypher = cypher
        self.file = None
        self.file_format = None
        self.selected_mode = tk.StringVar(self)
        self.selected_mode.set("ECB")

        self.navbar = Navbar(self)
        self.navbar.pack(side="top")

        self.bottom_frame = None
        self.switch_frame(HomePage)

    def switch_frame(self, frame):
        if self.bottom_frame is not None:
            self.bottom_frame.destroy()
        self.bottom_frame = frame(self)
        self.bottom_frame.pack(side="bottom")

    def open_file(self):
        f_types = [('all files', '*.*')]
        self.file_format, self.file = Utils.open_file(f_types, return_format=True)
