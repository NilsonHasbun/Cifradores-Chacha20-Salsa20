from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import socket
import json
import base64

# Funciones auxiliares para cifrar y descifrar
def encrypt_aes(key, plaintext, mode, iv=None):
    if mode == "ECB":
        cipher_mode = modes.ECB()
    elif mode == "CBC":
        cipher_mode = modes.CBC(iv)
    elif mode == "CTR":
        cipher_mode = modes.CTR(iv)
    else:
        raise ValueError("Modo no soportado")
    
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes(key, ciphertext, mode, iv=None):
    if mode == "ECB":
        cipher_mode = modes.ECB()
    elif mode == "CBC":
        cipher_mode = modes.CBC(iv)
    elif mode == "CTR":
        cipher_mode = modes.CTR(iv)
    else:
        raise ValueError("Modo no soportado")
    
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

# Servidor
def server():
    key = os.urandom(32)  # Clave AES de 256 bits
    iv = os.urandom(16)
    print(f"Clave AES generada: {base64.b64encode(key).decode()}")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 65432))
    server_socket.listen(1)
    print("Servidor en espera de conexión...")
    
    conn, addr = server_socket.accept()
    print(f"Conexión aceptada desde {addr}")
    
    data = conn.recv(1024).decode()
    request = json.loads(data)
    mode = request["mode"]
    security = request["security"]
    print(f"Modo: {mode}, Seguridad: {security}")
    
    encrypted_key = encrypt_aes(key, key, "CBC", iv)
    conn.send(base64.b64encode(encrypted_key) + b"||" + base64.b64encode(iv))
    print("Llave enviada al cliente.")
    
    while True:
        data = conn.recv(1024)
        if not data:
            break
        
        decrypted_message = decrypt_aes(key, base64.b64decode(data), mode, iv)
        print(f"Mensaje recibido: {decrypted_message.decode()}")
    
    conn.close()

if _name_ == "_main_":
    server()