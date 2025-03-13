import socket
from Crypto.Cipher import ChaCha20, Salsa20
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 65432

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        print("[*] Conectado al Servidor.")

        # 1. Elegir cifrador
        cipher_choice = input("Elige cifrador (Salsa20/ChaCha20): ")
        client.sendall(cipher_choice.encode())

        # 2. Recibir llave simétrica
        key = client.recv(32)  # 256 bits
        print(f"[*] Llave recibida: {key.hex()}")

        # 3. Crear cifrador
        plaintext = input("Ingresa el mensaje a cifrar: ").encode()
        nonce = get_random_bytes(8 if cipher_choice == "Salsa20" else 12)

        if cipher_choice == "Salsa20":
            cipher = Salsa20.new(key=key, nonce=nonce)
        elif cipher_choice == "ChaCha20":
            cipher = ChaCha20.new(key=key, nonce=nonce)
        else:
            print("[!] Cifrador no soportado")
            return

        ciphertext = cipher.encrypt(plaintext)

        # 4. Enviar nonce y mensaje cifrado
        client.sendall(nonce)
        client.sendall(ciphertext)
        print(f"[*] Mensaje cifrado enviado: {ciphertext.hex()}")

if __name__ == "__main__":
    main()
