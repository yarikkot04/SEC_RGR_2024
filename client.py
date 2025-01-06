import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import hashlib

HOST = '127.0.0.1'
PORT = 44444

def encrypt_with_public_key(data, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)

def encrypt_aes(message, session_key):
    from Crypto.Random import get_random_bytes
    iv = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(message))
    return iv, ciphertext

def decrypt_aes(iv, ciphertext, session_key):
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    plaintext = cipher_aes.decrypt(ciphertext)
    return unpad(plaintext)

def pad(data, block_size=16):
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def main():
    client_random = get_random_bytes(16)
    premaster_secret = get_random_bytes(24)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
        client_sock.connect((HOST, PORT))
        print("Connected to the server.")

        hello_msg = b"HELLO:" + client_random
        client_sock.sendall(hello_msg)

        data = client_sock.recv(4096)
        if not data:
            return

        msg_parts = data.split(b':', 2)
        server_random = msg_parts[1][:16]
        server_public_key = msg_parts[2]

        print(f"[Client] Got server_random={server_random.hex()}")
        print(f"[Client] Got server public key (PEM) length = {len(server_public_key)} bytes")

        encrypted_premaster = encrypt_with_public_key(premaster_secret, server_public_key)
        client_sock.sendall(encrypted_premaster)
        print("[Client] Sent encrypted premaster.")

        session_key_material = client_random + server_random + premaster_secret
        session_key = hashlib.sha256(session_key_material).digest()
        print(f"[Client] Session key = {session_key.hex()}")

        iv_client, enc_ready = encrypt_aes(b"CLIENT_FINISHED", session_key)
        client_sock.sendall(iv_client + enc_ready)
        print("[Client] Sent CLIENT_FINISHED in encrypted form.")

        ready_data = client_sock.recv(2048)
        if not ready_data:
            return
        iv_server = ready_data[:16]
        ciphertext_server = ready_data[16:]
        decrypted_ready_msg = decrypt_aes(iv_server, ciphertext_server, session_key)
        print(f"[Client] Server READY message decrypted: {decrypted_ready_msg}")

        secure_message = b"Hello from client (secure)!"
        iv_msg, enc_msg = encrypt_aes(secure_message, session_key)
        client_sock.sendall(iv_msg + enc_msg)
        print("[Client] Sent secure message to server.")

        encrypted_response = client_sock.recv(2048)
        if encrypted_response:
            iv_resp = encrypted_response[:16]
            ciphertext_resp = encrypted_response[16:]
            decrypted_resp = decrypt_aes(iv_resp, ciphertext_resp, session_key)
            print(f"[Client] Server response (decrypted) = {decrypted_resp.decode('utf-8', errors='ignore')}")

    print("Client finished.")

if __name__ == '__main__':
    main()
