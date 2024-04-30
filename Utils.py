import tkinter.filedialog
import os


class Utils:
    @staticmethod
    def save_file(file, file_format):
        file_path = tkinter.filedialog.asksaveasfilename(filetypes=[("All Files", "*.*")], defaultextension=file_format)
        with open(file_path, 'xb') as opened_file:
            opened_file.write(file)

    @staticmethod
    def open_file(f_types, return_format=False):
        try:
            path = tkinter.filedialog.askopenfilename(filetypes=f_types)
            with open(path, "rb") as file:
                if return_format:
                    file_format = Utils.get_format(path)
                    return file_format, file.read()
                else:
                    return file.read()
        except FileNotFoundError:
            pass

    @staticmethod
    def get_format(path):
        _, file_format = os.path.splitext(path)
        return file_format

    @staticmethod
    def calculate_speed(file, t1, t2):
        file_size = len(file) / (1024 * 1024)
        seconds = t2 - t1
        return round(file_size / seconds, 2)
