import tkinter as tk
from tkinter import filedialog, messagebox
import struct
import time
import os


class ChaCha20:
    def __init__(self):
        self.counter = 0

    def quarterround(self, a, b, c, d):
        # V tem koraku vsak izmed parametrov (a, b, c, d)
        # sodeluje pri operacijah seštevanja, odštevanja in XOR-a.
        # Rezultat vsake operacije je omejen na 32-bitno vrednost, kar je doseženo z uporabo
        # maskiranja z 0xFFFFFFFF.
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
        # Funkcija za generiranje enega bloka. Vsak blok vsebuje 64 bajtov (512 bitov)
        # keystreama, ki se uporablja za šifriranje podatkov. Blok inicializira stanje (state),
        # ki vsebuje 16 32-bitnih števil.
        x = [0] * 16
        x[:4] = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # Konstante
        x[4:7] = self.nonce  # IV (številka zaporedja)
        x[12] = self.counter & 0xFFFFFFFF
        x[13] = self.counter >> 32
        x[14:16] = self.key  # Ključ
        state = x[:]

        for _ in range(10):
            for i in range(0, 16, 4):
                # Izvedba 10 krogov četrt-rund na stanju. Vsak krog vpliva na vseh
                # 16 32-bitnih števil v stanju.
                state[i], state[i + 1], state[i + 2], state[i + 3] = self.quarterround(
                    state[i], state[i + 1], state[i + 2], state[i + 3]
                )
            for i in range(16):
                # Dodajanje stanja k začetnemu stanju (x) in omejitev
                # na 32 bitov s pomočjo maskiranja z 0xFFFFFFFF.
                state[i] = (state[i] + x[i]) & 0xFFFFFFFF

        packed_state = b"".join(struct.pack("<I", item) for item in state)
        return packed_state

    def encrypt(self, plaintext, key, iv):
        self.key = key
        self.nonce = iv
        ciphertext = bytearray()
        self.counter = 0

        for i in range(0, len(plaintext), 64):
            keystream = self.chacha_block()
            for j in range(min(64, len(plaintext) - i)):
                # Uporaba keystreama za XOR-anje podatkov v bloku s podatki.
                ciphertext.append(plaintext[i + j] ^ keystream[j])
            self.counter += 1

        return ciphertext

    def decrypt(self, ciphertext, key, iv):
        # Dešifriranje se izvaja na enak način kot šifriranje, saj je ChaCha20
        # simetrični algoritem. Znano mora biti enako stanje (ključ, IV) kot pri
        # šifriranju.
        return self.encrypt(ciphertext, key, iv)


class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ChaCha20 Cipher")
        self.cipher = ChaCha20()

        # Input frame
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

        self.output_label = tk.Label(
            self.input_frame, text="Output:", width=8, font=("Helvetica", 13, "bold")
        )
        self.output_label.grid(row=1, column=0)
        self.output_file_label = tk.Label(
            self.input_frame, text="<Decrypt a file..>", width=45
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
        self.encrypted_content = None
        self.decrypted_content = None
        self.encryption_mode = True  # True for encryption, False for decryption

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
        messagebox.showinfo("Saved", "Output saved successfully!")

    def encrypt_file(self):
        if self.loaded_file_content:
            key = os.urandom(32)  # Generate a new random key for encryption
            iv = os.urandom(12)  # Generate a new random IV for encryption
            start = time.time()
            self.encrypted_content = self.cipher.encrypt(
                self.loaded_file_content, key, iv
            )
            end = time.time()
            print(
                f"Encryption speed: {len(self.loaded_file_content) / (end - start)} B/s"
            )
            print(f"Elapsed time: {end - start}s")
            self.output_file_label.config(text="File encrypted!")
            self.encryption_mode = True
        else:
            messagebox.showerror("Error", "No file loaded!")

    def decrypt_file(self):
        if self.loaded_file_content:
            # We assume that the key and IV are known
            key = self.cipher.key  # Use the key from the ChaCha20 instance
            iv = self.cipher.nonce  # Use the IV from the ChaCha20 instance
            start = time.time()
            self.decrypted_content = self.cipher.decrypt(
                self.loaded_file_content, key, iv
            )
            end = time.time()
            print(
                f"Decryption speed: {len(self.loaded_file_content) / (end - start)} B/s"
            )
            print(f"Elapsed time: {end - start}s")
            self.output_file_label.config(text="File decrypted!")
            self.encryption_mode = False
        else:
            messagebox.showerror("Error", "No file loaded!")


if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
