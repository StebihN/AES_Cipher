import tkinter as tk

from Cipher.AES import AES
from Interface.MainApp import MainApp

if __name__ == "__main__":
    root = tk.Tk()
    root.title('AES Encryption')
    root.geometry("280x280")

    cipher = AES()
    MainApp(root, cipher).pack()

    root.mainloop()
