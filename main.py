import tkinter as tk
from Interface import Interface
from AES import AES
if __name__ == "__main__":
    root = tk.Tk()
    root.title('AES Encryption')
    root.geometry("280x280")

    cypher = AES()
    Interface(root, cypher).pack()

    root.mainloop()
