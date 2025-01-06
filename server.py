import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import hashlib

HOST = '127.0.0.1'
PORT = 44444

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def decrypt_with_private_key(encrypted_data, private_key_pem):
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_data)

def encrypt_aes(message, session_key):
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
    private_key_pem, public_key_pem = generate_rsa_keypair()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)
        print(f"Server is listening on {HOST}:{PORT}")

        client_conn, addr = server_sock.accept()
        with client_conn:
            print(f"Connected by {addr}")

            data = client_conn.recv(1024)
            if not data:
                return
            msg_parts = data.split(b':')
            client_message = msg_parts[0]
            client_random = msg_parts[1]

            print(f"[Server] Got client message: {client_message}, client_random={client_random.hex()}")

            server_random = get_random_bytes(16)
            server_hello = b"SERVER_HELLO:" + server_random + b":" + public_key_pem

            client_conn.sendall(server_hello)

            encrypted_premaster = client_conn.recv(2048)
            print(f"[Server] Encrypted premaster received, len={len(encrypted_premaster)} bytes")

            premaster_secret = decrypt_with_private_key(encrypted_premaster, private_key_pem)
            print(f"[Server] Decrypted premaster = {premaster_secret.hex()}")

            session_key_material = client_random + server_random + premaster_secret
            session_key = hashlib.sha256(session_key_material).digest()
            print(f"[Server] Session key = {session_key.hex()}")

            ready_data = client_conn.recv(2048)
            if not ready_data:
                return

            iv_client = ready_data[:16]
            ciphertext_client = ready_data[16:]
            decrypted_ready_msg = decrypt_aes(iv_client, ciphertext_client, session_key)
            print(f"[Server] Got READY from client (decrypted) = {decrypted_ready_msg}")

            iv_server, encrypted_ready = encrypt_aes(b"SERVER_FINISHED", session_key)
            client_conn.sendall(iv_server + encrypted_ready)

            encrypted_msg = client_conn.recv(2048)
            if encrypted_msg:
                iv_client_msg = encrypted_msg[:16]
                ciphertext_client_msg = encrypted_msg[16:]
                decrypted_msg = decrypt_aes(iv_client_msg, ciphertext_client_msg, session_key)
                print(f"[Server] Client's secure message = {decrypted_msg.decode('utf-8', errors='ignore')}")

            response = b"Hello from server (secure)!"
            iv_resp, enc_resp = encrypt_aes(response, session_key)
            client_conn.sendall(iv_resp + enc_resp)

    print("Server finished.")

if __name__ == '__main__':
    main()
