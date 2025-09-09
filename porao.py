# porao.py

from detector import DetectorMalware
from yara_scanner import YaraScanner
import os
import pathlib
import psutil
import time
import subprocess
import regex as re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import sys
import math
import zipfile

# --- VARIÁVEIS GLOBAIS E CONFIGURAÇÃO ---
username = os.getlogin()
ult_processos = []
change_type = [0, 0, 0, 0, 0]
last_activity_time = time.time()
active_threat = False
arquivos_criados_recentemente = []

HOME_DIR = os.path.expanduser('~')
CANARY_FILES = {
    os.path.join(HOME_DIR, 'Documents', 'dados_bancarios.xlsx'),
    os.path.join(HOME_DIR, 'Documents', 'senhas_importantes.txt'),
    os.path.join(HOME_DIR, 'Pictures', 'fotos_viagem_secreta.zip'),
    os.path.join(HOME_DIR, 'Desktop', 'trabalho_faculdade.docx')
}
QUARANTINE_DIR = os.path.join(HOME_DIR, "Quarantine")
QUARANTINE_PASS = b"infected"

# ***** MELHORIA 2: ATAQUE PREVENTIVO *****
# Lista de pastas onde a execução de novos processos é considerada imediatamente suspeita.
FORBIDDEN_EXEC_PATHS = [
    os.environ.get("TEMP", "").lower(),
    os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp").lower()
]
# Remove entradas vazias caso as variáveis de ambiente não existam
FORBIDDEN_EXEC_PATHS = [path for path in FORBIDDEN_EXEC_PATHS if path]


# --- FUNÇÕES DE DETECÇÃO E PROTEÇÃO ---

def calculate_entropy(data: bytes) -> float:
    if not data: return 0
    entropy = 0; freq_dict = {}
    for byte in data: freq_dict[byte] = freq_dict.get(byte, 0) + 1
    data_len = len(data)
    for count in freq_dict.values():
        p_x = count / data_len
        if p_x > 0: entropy -= p_x * math.log2(p_x)
    return entropy

def check_ransom_note_filename(file_path: str) -> bool:
    filename = os.path.basename(file_path)
    pattern = re.compile(r'((DECRYPT|RECOVER|RESTORE|HELP|INSTRUCTIONS).*\.(txt|html|hta))|restore_files_.*\.txt', re.IGNORECASE)
    if pattern.match(filename):
        print(f"\n🚨 AMEAÇA DETECTADA (NOTA DE RESGATE)! Arquivo: '{filename}'")
        return True
    return False

def colocar_em_quarentena(file_path: str):
    if not os.path.exists(file_path) or not os.path.isfile(file_path): return
    print(f"[*] Movendo para quarentena: {os.path.basename(file_path)}")
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        zip_name = f"{os.path.basename(file_path)}_{timestamp}.zip"
        zip_path = os.path.join(QUARANTINE_DIR, zip_name)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.setpassword(QUARANTINE_PASS)
            zf.write(file_path, arcname=os.path.basename(file_path))
        os.remove(file_path)
        print(f"[+] Arquivo movido para '{zip_path}' e protegido com senha.")
    except Exception as e:
        print(f"[-] Falha ao mover para quarentena: {e}")

def deletar_nota_resgate(file_path: str):
    print(f"[*] Nota de resgate detectada. Deletando arquivo: {os.path.basename(file_path)}")
    try:
        os.remove(file_path)
        print(f"[+] Arquivo '{os.path.basename(file_path)}' deletado com sucesso.")
    except Exception as e:
        print(f"[-] Falha ao deletar nota de resgate: {e}")

def quarentena_em_massa():
    global arquivos_criados_recentemente
    print(f"\n[*] Iniciando quarentena em massa para {len(arquivos_criados_recentemente)} arquivo(s) recente(s)...")
    for file_path in list(arquivos_criados_recentemente):
        colocar_em_quarentena(file_path)
    arquivos_criados_recentemente.clear()

def encerrar_proctree():
    global ult_processos, active_threat
    if active_threat: return
    active_threat = True
    print("\n" + "🚨 AMEAÇA DETECTADA! ACIONANDO PROTOCOLO DE MITIGAÇÃO! 🚨")
    quarentena_em_massa()
    meu_pid = os.getpid()
    pids_to_kill = ""
    for pid in reversed(ult_processos):
        if psutil.pid_exists(pid) and pid != meu_pid:
            pids_to_kill += f"/PID {pid} "
    if pids_to_kill:
        print(f"Encerrando processos suspeitos (PIDs): {pids_to_kill.replace('/PID', '').strip()}")
        subprocess.run(f"taskkill {pids_to_kill}/F /T", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ult_processos.clear()
    print("Processos suspeitos encerrados. O monitoramento continua ativo.")
    time.sleep(10)
    active_threat = False

def avaliar_heuristica():
    global change_type
    criados, modificados, movidos, deletados, honeypot = change_type
    if honeypot > 0: return True
    # ***** MELHORIA 3: HEURÍSTICA MAIS SENSÍVEL *****
    if modificados > 15 and criados > 5: return True # Limites reduzidos de 30/10 para 15/5
    if deletados > 25: return True # Limite reduzido de 50 para 25
    return False

def extrair_extensao(file: str):
    extensions = [".exe", ".dll", ".com", ".bat", ".vbs", ".ps1"]
    file_extension = pathlib.Path(file).suffix
    return file_extension.lower() in extensions

def novos_processos():
    global ult_processos
    now = time.time()
    current_pids = []
    for process in psutil.process_iter(['pid', 'create_time', 'cmdline', 'exe']):
        try:
            # ***** MELHORIA 2: ATAQUE PREVENTIVO *****
            # Pega o caminho do executável do processo
            exe_path = process.info.get('exe')
            if exe_path:
                # Verifica se o processo está rodando de uma pasta proibida
                for forbidden_path in FORBIDDEN_EXEC_PATHS:
                    if exe_path.lower().startswith(forbidden_path):
                        print(f"\n🚨 ALERTA PREVENTIVO! Processo suspeito executando de pasta temporária: {exe_path}")
                        if process.info['pid'] not in ult_processos:
                            ult_processos.append(process.info['pid'])
                        encerrar_proctree()
                        return # Ação imediata

            cmdline_list = process.info['cmdline']
            cmdline = " ".join(cmdline_list).lower() if cmdline_list else ""
            if "vssadmin" in cmdline and "delete" in cmdline and "shadows" in cmdline:
                if process.info['pid'] not in ult_processos:
                    ult_processos.append(process.info['pid'])
                encerrar_proctree()
                return
            if (now - process.info['create_time']) < 120:
                if process.info['pid'] not in ult_processos:
                    ult_processos.append(process.info['pid'])
                current_pids.append(process.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    ult_processos = [pid for pid in ult_processos if pid in current_pids]

class MonitorFolder(FileSystemEventHandler):
    # (Nenhuma mudança necessária nesta classe, ela permanece igual)
    def __init__(self, yara_scanner: YaraScanner):
        self.yara_scanner = yara_scanner
        super().__init__()

    def _analyze_file(self, file_path, is_new_file=False):
        for attempt in range(3):
            try:
                if check_ransom_note_filename(file_path):
                    deletar_nota_resgate(file_path); encerrar_proctree(); return
                if self.yara_scanner.scan_file(file_path):
                    colocar_em_quarentena(file_path); encerrar_proctree(); return
                if is_new_file and extrair_extensao(file_path):
                    detector = DetectorMalware(file_path)
                    if detector.is_malware():
                        colocar_em_quarentena(file_path); encerrar_proctree(); return
                if not is_new_file:
                    with open(file_path, "rb") as f:
                        data = f.read()
                    entropy = calculate_entropy(data)
                    if entropy > 7.2:
                        print(f"\n🚨 ALERTA DE ENTROPIA! '{os.path.basename(file_path)}' parece criptografado.")
                        colocar_em_quarentena(file_path); encerrar_proctree(); return
                break
            except (IOError, PermissionError):
                time.sleep(0.1)
            except Exception:
                break

    def on_any_event(self, event):
        global last_activity_time
        last_activity_time = time.time()
        if avaliar_heuristica(): encerrar_proctree()
    
    def on_created(self, event):
        if event.is_directory: return
        arquivos_criados_recentemente.append(event.src_path)
        change_type[0] += 1
        self._analyze_file(event.src_path, is_new_file=True)

    def on_deleted(self, event):
        if event.is_directory: return
        change_type[3] += 1

    def on_modified(self, event):
        if event.is_directory: return
        change_type[1] += 1
        if event.src_path in CANARY_FILES:
            print(f"\n🚨 ALERTA MÁXIMO! Arquivo isca '{os.path.basename(event.src_path)}' foi modificado!")
            encerrar_proctree(); return
        self._analyze_file(event.src_path, is_new_file=False)

    def on_moved(self, event):
        change_type[2] += 1
        if event.src_path in CANARY_FILES or event.dest_path in CANARY_FILES:
            print(f"\n🚨 ALERTA MÁXIMO! Arquivo isca '{os.path.basename(event.src_path)}' foi movido/renomeado!")
            encerrar_proctree(); return

if __name__ == "__main__":
    print("Verificando arquivos isca (Canary Files)...")
    for f in CANARY_FILES:
        if not os.path.exists(f):
            try:
                pathlib.Path(os.path.dirname(f)).mkdir(parents=True, exist_ok=True)
                pathlib.Path(f).touch(); print(f" -> Criado arquivo isca: {f}")
            except Exception as e:
                print(f" -> Erro ao criar arquivo isca {f}: {e}")

    scanner = YaraScanner()
    if scanner.rules is None: exit()
    
    # ***** MELHORIA 1: EXPANDIR ÁREA DE MONITORAMENTO *****
    paths_to_watch = [os.path.join(HOME_DIR, d) for d in ['Downloads', 'Documents', 'Desktop', 'Pictures']]
    # Adiciona pastas temporárias à lista de monitoramento
    temp_paths = [os.environ.get("TEMP"), os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp")]
    for path in temp_paths:
        if path and os.path.exists(path) and path not in paths_to_watch:
            paths_to_watch.append(path)

    event_handler = MonitorFolder(yara_scanner=scanner)
    observer = Observer()
    
    print("\nIniciando monitoramento...")
    for path in paths_to_watch:
        if os.path.exists(path):
            observer.schedule(event_handler, path=path, recursive=True); print(f" -> Monitorando: {path}")
        else:
            print(f" -> Aviso: O diretório '{path}' não existe.")

    observer.start()
    spinner_states = ['-', '\\', '|', '/']
    spinner_index = 0
    
    try:
        while True:
            spinner_char = spinner_states[spinner_index]
            sys.stdout.write(f"\rMonitorando ativamente... {spinner_char}"); sys.stdout.flush()
            spinner_index = (spinner_index + 1) % len(spinner_states)
            novos_processos()
            if time.time() - last_activity_time > 15:
                change_type = [0, 0, 0, 0, 0]
                arquivos_criados_recentemente.clear()
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado pelo usuário.")
        observer.stop()
    observer.join()