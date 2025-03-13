import socket
import os
from Crypto.Cipher import ChaCha20, Salsa20
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 65432

def generate_key():
    return get_random_bytes(32)  # 256 bits para ChaCha20 y Salsa20

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()
        print(f"[*] Servidor escuchando en {HOST}:{PORT}...")

        conn, addr = server.accept()
        with conn:
            print(f"[*] Conexión establecida con {addr}")

            # 1. Recibir la elección del cifrador
            cipher_choice = conn.recv(1024).decode()
            print(f"[*] Cliente eligió: {cipher_choice}")

            # 2. Generar y enviar la llave simétrica
            key = generate_key()
            conn.sendall(key)
            print(f"[*] Llave enviada al Cliente: {key.hex()}")

            # 3. Recibir datos cifrados
            nonce = conn.recv(24)  # Nonce de 8 o 12 bytes según cifrador
            ciphertext = conn.recv(1024)

            # 4. Descifrar datos
            if cipher_choice == "Salsa20":
                cipher = Salsa20.new(key=key, nonce=nonce)
            elif cipher_choice == "ChaCha20":
                cipher = ChaCha20.new(key=key, nonce=nonce)
            else:
                print("[!] Cifrador no soportado")
                return

            plaintext = cipher.decrypt(ciphertext)
            print(f"[*] Mensaje descifrado: {plaintext.decode()}")

if __name__ == "__main__":
    main()
