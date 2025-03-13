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

def apply_security(key, data, mode, iv, security):
    if security == "doble":
        data = encrypt_aes(key, data, mode, iv)
        data = encrypt_aes(key, data, mode, iv)
    elif security == "triple":
        data = encrypt_aes(key, data, mode, iv)
        data = decrypt_aes(key, data, mode, iv)
        data = encrypt_aes(key, data, mode, iv)
    elif security == "blanqueo":
        whitened_key = bytes(a ^ b for a, b in zip(key, iv))
        data = encrypt_aes(whitened_key, data, mode, iv)
    else:
        data = encrypt_aes(key, data, mode, iv)
    return data

def client(server_ip):
    key = input("Ingrese la clave compartida en Base64: ")
    key = base64.b64decode(key)
    mode = input("Seleccione modo AES (ECB, CBC, CTR): ")
    security = input("Seleccione seguridad (ninguna, doble, triple, blanqueo): ")
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, 65432))
    
    request = json.dumps({"mode": mode, "security": security})
    client_socket.send(request.encode())
    
    encrypted_data = client_socket.recv(1024).split(b"||")
    encrypted_key = base64.b64decode(encrypted_data[0])
    iv = base64.b64decode(encrypted_data[1])
    
    key = decrypt_aes(key, encrypted_key, "CBC", iv)
    print("Clave de sesión recibida correctamente.")
    
    while True:
        message = input("Ingrese mensaje a enviar (Ingrese SALIR para terminar la comunicación): ")
        if message.lower() == "salir":
            break
        
        encrypted_message = apply_security(key, message.encode(), mode, iv, security)
        print(f"Mensaje cifrado: {base64.b64encode(encrypted_message).decode()}")

        client_socket.send(base64.b64encode(encrypted_message))
    
    client_socket.close()

if __name__ == "__main__":
    ip = '127.0.0.1'
    client(ip)