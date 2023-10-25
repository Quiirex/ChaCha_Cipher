import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import struct
import random
import time

CONST_QUARTERROUND = lambda a, b, c, d: ((a + b) % 232, d ^ a, c + d, (b + c) % 232)
CHA_CONST = lambda a: (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


class ChaCha:
    def __init__(self):
        self.key = bytearray(32)
        self.nonce = bytearray(12)
        random.seed()
        for i in range(32):
            self.key[i] = random.randint(0, 255)
        for i in range(12):
            self.nonce[i] = random.randint(0, 255)

    def quarterround(self, a, b, c, d):
        return CONST_QUARTERROUND(a, b, c, d)

    def chacha_block(self, counter):
        x = [0] * 16
        x[0:] = CHA_CONST(0)
        x[4:8] = struct.unpack("<L", self.nonce[:4])
        x[8:12] = struct.unpack("<L", self.nonce[4:8])
        x[12] = counter >> 32
        x[13] = counter & 0xFFFFFFFF
        x[14:16] = struct.unpack("<L", self.key[:4])

        for i in range(10):
            for j in range(16):
                x[j] += self.key[(j % 16)]
                self.quarterround(
                    x[(j - 1) % 16], x[j], x[(j + 1) % 16], x[(j + 14) % 16]
                )

        out = bytearray(64)
        for i in range(16):
            out[i * 4 : (i + 1) * 4] = struct.pack("<L", x[i])

        return out

    def encrypt(self, plaintext):
        counter = 0
        ciphertext = bytearray()
        for i in range(0, len(plaintext), 64):
            block = self.chacha_block(counter)
            for j in range(min(64, len(plaintext) - i)):
                ciphertext.append(plaintext[i + j] ^ block[j])
            counter += 1

        return ciphertext

    def decrypt(self, ciphertext):
        counter = 0
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 64):
            block = self.chacha_block(counter)
            for j in range(min(64, len(ciphertext) - i)):
                plaintext.append(ciphertext[i + j] ^ block[j])
            counter += 1

        return plaintext


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
        if self.loaded_file_content:
            start = time.time()
            ciphertext = self.cipher.encrypt(self.loaded_file_content)
            end = time.time()
            print(
                f"Encryption speed: {len(self.loaded_file_content)/(end-start)/1000} kB/s"
            )
            self.output_file_label.config(text="File encrypted!")
        else:
            messagebox.showerror("Error", "No file loaded!")

    def decrypt_file(self):
        if self.loaded_file_content:
            start = time.time()
            plaintext = self.cipher.decrypt(self.loaded_file_content)
            end = time.time()
            print(
                f"Decryption speed: {len(self.loaded_file_content)/(end-start)/1000} kB/s"
            )
            self.output_file_label.config(text="File decrypted!")
        else:
            messagebox.showerror("Error", "No file loaded!")


if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
