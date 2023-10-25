import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import struct


class ChaCha:
    def __init__(self):
        pass


class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ChaCha20 Cipher")
        self.cipher = ChaCha()

        # Input frame
        self.input_frame = tk.Frame(root)
        self.input_frame.grid(row=0, column=0, padx=20, pady=20)

        self.text_label = tk.Label(
            self.input_frame, text="Input:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=0, column=0)
        self.loaded_file_label = tk.Label(
            self.input_frame, text="<No file loaded>", width=35
        )
        self.loaded_file_label.grid(row=0, column=1)

        self.output_label = tk.Label(
            self.input_frame, text="Output:", width=8, font=("Helvetica", 13, "bold")
        )
        self.output_label.grid(row=1, column=0)
        self.output_file_label = tk.Label(
            self.input_frame, text="<Decrypt a file..>", width=35
        )
        self.output_file_label.grid(row=1, column=1)

        self.save_output_button = tk.Button(
            self.input_frame, text="Save as..", command=self.save_output, width=5
        )
        self.save_output_button.grid(row=1, column=2)

        # Button frame
        self.button_frame = tk.Frame(root)
        self.button_frame.grid(row=4, column=0, padx=20, pady=20)

        self.load_file_button = tk.Button(
            self.button_frame,
            text="Load file..",
            command=self.load_file,
            width=10,
        )
        self.load_file_button.grid(row=1, column=0)

        self.encrypt_button = tk.Button(
            self.button_frame, text="Encrypt", command=self.encrypt_file, width=10
        )
        self.encrypt_button.grid(row=1, column=2)

        self.decrypt_button = tk.Button(
            self.button_frame, text="Decrypt", command=self.decrypt_file, width=10
        )
        self.decrypt_button.grid(row=1, column=3)

        self.loaded_file_content = None

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if file_path:
            self.loaded_file_label.config(text=file_path.split("/")[-1])
            with open(file_path, "rb") as file:
                self.loaded_file_content = file.read()
                self.output_file_label.config(text="File loaded.")
        else:
            self.loaded_file_label.config(text="<No file loaded>")
            self.output_file_label.config(text="<Encrypt/Decrypt a file..>")

    def save_output(self):
        output_text = self.output_box.get("1.0", tk.END)
        file_path = filedialog.asksaveasfilename(filetypes=[("All Files", "*.*")])
        with open(file_path, "w") as file:
            file.write(output_text)
        messagebox.showinfo("Saved", "Output saved successfully!")

    def encrypt_file(self):
        pass

    def decrypt_file(self):
        pass


if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
