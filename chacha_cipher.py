from tkinter import filedialog, messagebox
import tkinter as tk
import struct
import time
import os


class ChaCha20:
    def __init__(self):
        self.key = None
        self.nonce = None
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
        # Blok inicializira stanje, ki vsebuje 16 32-bitnih števil.
        state = [0] * 16
        state[:4] = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # Konstante
        state[4:12] = self.key
        state[12] = self.counter & 0xFFFFFFFF
        state[13] = (self.counter >> 32) & 0xFFFFFFFF
        state[14:16] = self.nonce

        for _ in range(10):
            for i in range(0, 16, 4):
                # Izvedba 10 krogov četrt-rund na stanju.
                # Vsak krog vpliva na vseh 16 32-bitnih števil v stanju.
                state[i], state[i + 1], state[i + 2], state[i + 3] = self.quarter_round(
                    state[i], state[i + 1], state[i + 2], state[i + 3]
                )
            for i in range(16):
                # Dodajanje stanja k začetnemu stanju (x) in omejitev na 32 bitov, ostalo se odreže.
                state[i] = (state[i] + state[i]) & 0xFFFFFFFF

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
        # Za dešifriranje potrebujemo enako stanje (ključ, nonce) kot pri šifriranju.
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
            self.input_frame, text="Nonce:", width=8, font=("Helvetica", 13, "bold")
        )
        self.text_label.grid(row=2, column=0)
        self.nonce_label = tk.Label(
            self.input_frame, text="<No nonce loaded>", width=45
        )
        self.nonce_label.grid(row=2, column=1)

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
            text="Load file..",
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

        self.generate_nonce_button = tk.Button(
            self.button_frame,
            text="Generate nonce",
            command=self.generate_nonce,
            width=8,
        )
        self.generate_nonce_button.grid(row=2, column=0)

        self.load_nonce_button = tk.Button(
            self.button_frame, text="Load nonce..", command=self.load_nonce, width=8
        )
        self.load_nonce_button.grid(row=2, column=1)

        self.generate_key_button = tk.Button(
            self.button_frame, text="Generate key", command=self.generate_key, width=8
        )
        self.generate_key_button.grid(row=1, column=0)

        self.upload_key_button = tk.Button(
            self.button_frame, text="Load key..", command=self.load_key, width=8
        )
        self.upload_key_button.grid(row=1, column=1)

    def generate_nonce(self):
        self.cipher.nonce = os.urandom(12)
        self.nonce_label.config(text="Nonce generated and loaded.")
        self.save_nonce()

    def save_nonce(self):
        nonce = self.cipher.nonce
        if nonce:
            file_path = filedialog.asksaveasfilename(
                filetypes=[("Text Files", "*.txt")]
            )
            with open(file_path, "wb") as file:
                file.write(nonce)
        else:
            messagebox.showerror("Error", "No nonce generated to save!")

    def load_nonce(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "rb") as file:
                self.cipher.nonce = file.read()
                self.nonce_label.config(text="nonce loaded.")
        else:
            messagebox.showerror("Error", "No nonce uploaded!")

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
            self.output_file_label.config(text="<Encrypt/decrypt a file..>")

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
            print(f"Starting encryption..")
            self.encrypted_content = self.cipher.encrypt(self.loaded_file_content)
            print(f"Encryption finished!")
            end = time.time()
            print(
                f"Encryption speed: {round((len(self.loaded_file_content) / (end - start)), 2)} B/s"
            )
            print(f"Elapsed time: {round((end - start), 2)}s")
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
            print(f"Starting decryption..")
            self.decrypted_content = self.cipher.decrypt(self.loaded_file_content)
            print(f"Decryption finished!")
            end = time.time()
            print(
                f"Decryption speed: {round((len(self.loaded_file_content) / (end - start)), 2)} B/s"
            )
            print(f"Elapsed time: {round((end - start), 2)}s")
            self.output_file_label.config(text="File decrypted!")
            self.encryption_mode = False
            self.save_output()
        else:
            messagebox.showerror("Error", "No file loaded!")


if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
