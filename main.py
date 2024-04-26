import tkinter as tk
from Interface import Interface

if __name__ == "__main__":
    root = tk.Tk()
    root.title('AES Encryption')
    root.geometry("280x280")

    Interface(root).pack()

    root.mainloop()
