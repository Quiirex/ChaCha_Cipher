import tkinter as tk
from tkinter import filedialog, messagebox
import struct
import time
import os


class ChaCha20:
    def __init__(self):
        self.key = None
        self.iv = None
        self.counter = 0

    def quarter_round(self, a, b, c, d):
        # Seštevanje, odštevanje in XOR-anje.
        # Rezultat vsake operacije je omejen na 32-bitno vrednost, ostalo se odreže.
        a = (a + b) & 0xFFFFFFFF
        d = (d ^ a) & 0xFFFFFFFF
        c = (c + d) & 0xFFFFFFFF
        b = (b ^ c) & 0xFFFFFFFF
        a = (a + b) & 0xFFFFFFFF
        d = (d ^ a) & 0xFFFFFFFF
        c = (c + d) & 0xFFFFFFFF
        b = (b ^ c) & 0xFFFFFFFF
        return a, b, c, d

    def chacha_block(self):
        # Generiranje enega bloka. Vsak blok vsebuje 64 bajtov (512 bitov) toka ključev.
        # Blok inicializira stanje, ki vsebuje 16 32-bitnih števil.
        x = [0] * 16
        x[:4] = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # Konstante
        x[4:7] = self.iv
        x[12] = self.counter & 0xFFFFFFFF
        x[13] = self.counter >> 32
        x[14:16] = self.key
        state = x[:]

        for _ in range(10):
            for i in range(0, 16, 4):
                # Izvedba 10 krogov četrt-rund na stanju. Vsak krog vpliva na vseh 16 32-bitnih števil v stanju.
                state[i], state[i + 1], state[i + 2], state[i + 3] = self.quarter_round(
                    state[i], state[i + 1], state[i + 2], state[i + 3]
                )
            for i in range(16):
                # Dodajanje stanja k začetnemu stanju (x) in omejitev na 32 bitov
                state[i] = (state[i] + x[i]) & 0xFFFFFFFF

        packed_state = b"".join(struct.pack("<I", item) for item in state)
        return packed_state

    def encrypt(self, plaintext):
        ciphertext = bytearray()
        self.counter = 0

        for i in range(0, len(plaintext), 64):
            keystream = self.chacha_block()
            for j in range(min(64, len(plaintext) - i)):
                # Uporaba toka ključev za XOR-anje podatkov v bloku s podatki.
                ciphertext.append(plaintext[i + j] ^ keystream[j])
            self.counter += 1

        return ciphertext

    def decrypt(self, ciphertext):
        # Za dešifriranje potrebujemo enako stanje (ključ, IV) kot pri šifriranju.
        return self.encrypt(ciphertext)


class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ChaCha20 Cipher")
        self.cipher = ChaCha20()

        self.input_frame = tk.Frame(root)
        self.input_frame.grid(row=0, column=0, padx=20, pady=20)

        self.text_label = tk.Label(
            self.input_frame, text="Input:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=0, column=0)
        self.loaded_file_label = tk.Label(
            self.input_frame, text="<No file loaded>", width=45
        )
        self.loaded_file_label.grid(row=0, column=1)

        self.text_label = tk.Label(
            self.input_frame, text="Key:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=1, column=0)
        self.key_label = tk.Label(self.input_frame, text="<No key loaded>", width=45)
        self.key_label.grid(row=1, column=1)

        self.text_label = tk.Label(
            self.input_frame, text="IV:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=2, column=0)
        self.iv_label = tk.Label(self.input_frame, text="<No IV loaded>", width=45)
        self.iv_label.grid(row=2, column=1)

        self.output_label = tk.Label(
            self.input_frame, text="Output:", width=8, font=("Helvetica", 13, "bold")
        )
        self.output_label.grid(row=3, column=0)
        self.output_file_label = tk.Label(
            self.input_frame, text="<Encrypt/Decrypt a file..>", width=45
        )
        self.output_file_label.grid(row=3, column=1)

        self.button_frame = tk.Frame(root)
        self.button_frame.grid(row=4, column=0, padx=20, pady=20)

        self.load_file_button = tk.Button(
            self.button_frame,
            text="Load File..",
            command=self.load_file,
            width=8,
        )
        self.load_file_button.grid(row=0, column=0)

        self.encrypt_button = tk.Button(
            self.button_frame, text="Encrypt", command=self.encrypt_file, width=8
        )
        self.encrypt_button.grid(row=3, column=0)

        self.decrypt_button = tk.Button(
            self.button_frame, text="Decrypt", command=self.decrypt_file, width=8
        )
        self.decrypt_button.grid(row=3, column=1)

        self.loaded_file_content = None
        self.encrypted_content = None
        self.decrypted_content = None
        self.encryption_mode = True  # True za šifriranje, False za dešifriranje

        self.generate_iv_button = tk.Button(
            self.button_frame, text="Generate IV", command=self.generate_iv, width=8
        )
        self.generate_iv_button.grid(row=2, column=0)

        self.load_iv_button = tk.Button(
            self.button_frame, text="Load IV..", command=self.load_iv, width=8
        )
        self.load_iv_button.grid(row=2, column=1)

        self.generate_key_button = tk.Button(
            self.button_frame, text="Generate Key", command=self.generate_key, width=8
        )
        self.generate_key_button.grid(row=1, column=0)

        self.upload_key_button = tk.Button(
            self.button_frame, text="Load Key..", command=self.load_key, width=8
        )
        self.upload_key_button.grid(row=1, column=1)

    def generate_iv(self):
        self.cipher.iv = os.urandom(12)
        self.iv_label.config(text="IV generated and loaded.")
        self.save_iv()

    def save_iv(self):
        iv = self.cipher.iv
        if iv:
            file_path = filedialog.asksaveasfilename(
                filetypes=[("Text Files", "*.txt")]
            )
            with open(file_path, "wb") as file:
                file.write(iv)
        else:
            messagebox.showerror("Error", "No IV generated to save!")

    def load_iv(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "rb") as file:
                self.cipher.iv = file.read()
                self.iv_label.config(text="IV loaded.")
        else:
            messagebox.showerror("Error", "No IV uploaded!")

    def generate_key(self):
        self.cipher.key = os.urandom(32)
        self.key_label.config(text="Key generated and loaded.")
        self.save_key()

    def save_key(self):
        if self.cipher.key:
            file_path = filedialog.asksaveasfilename(
                filetypes=[("Text Files", "*.txt")]
            )
            with open(file_path, "wb") as file:
                file.write(self.cipher.key)
        else:
            messagebox.showerror("Error", "No key generated to save!")

    def load_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "rb") as file:
                self.cipher.key = file.read()
                print(f"load_key, self.cipher.key: {self.cipher.key}")
                self.key_label.config(text="Key loaded.")
        else:
            messagebox.showerror("Error", "No key uploaded!")

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if file_path:
            self.loaded_file_label.config(text=f'"{file_path.split("/")[-1]}"')
            with open(file_path, "rb") as file:
                self.loaded_file_content = file.read()
                self.output_file_label.config(text="File loaded and ready.")
        else:
            self.loaded_file_label.config(text="<No file loaded>")
            self.output_file_label.config(text="<Encrypt/Decrypt a file..>")

    def save_output(self):
        if self.encryption_mode and self.encrypted_content:
            content = self.encrypted_content
        elif not self.encryption_mode and self.decrypted_content:
            content = self.decrypted_content
        else:
            messagebox.showerror("Error", "No content to save!")
            return

        file_path = filedialog.asksaveasfilename(filetypes=[("All Files", "*.*")])
        with open(file_path, "wb") as file:
            file.write(content)

    def encrypt_file(self):
        if self.loaded_file_content:
            if self.cipher.key is None:
                messagebox.showerror("Error", "No key loaded!")
                return
            start = time.time()
            self.encrypted_content = self.cipher.encrypt(self.loaded_file_content)
            end = time.time()
            print(
                f"Encryption speed: {len(self.loaded_file_content) / (end - start)} B/s"
            )
            print(f"Elapsed time: {end - start}s")
            self.output_file_label.config(text="File encrypted!")
            self.encryption_mode = True
            self.save_output()
        else:
            messagebox.showerror("Error", "No file loaded!")

    def decrypt_file(self):
        if self.loaded_file_content:
            if self.cipher.key is None:
                messagebox.showerror("Error", "No key loaded!")
                return
            start = time.time()
            self.decrypted_content = self.cipher.decrypt(self.loaded_file_content)
            end = time.time()
            print(
                f"Decryption speed: {len(self.loaded_file_content) / (end - start)} B/s"
            )
            print(f"Elapsed time: {end - start}s")
            self.output_file_label.config(text="File decrypted!")
            self.encryption_mode = False
            self.save_output()
        else:
            messagebox.showerror("Error", "No file loaded!")


if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
