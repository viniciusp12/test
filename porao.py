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

# --- VARIÁVEIS GLOBAIS E CONFIGURAÇÃO ---
username = os.getlogin()
ult_processos = []
change_type = [0, 0, 0, 0, 0] # [criados, modificados, movidos, deletados, honeypot]
last_activity_time = time.time()
active_threat = False

# --- !! IMPORTANTE: CONFIGURE SEUS ARQUIVOS ISCA AQUI !! ---
HOME_DIR = os.path.expanduser('~')
CANARY_FILES = {
    os.path.join(HOME_DIR, 'Documents', 'dados_bancarios.xlsx'),
    os.path.join(HOME_DIR, 'Documents', 'senhas_importantes.txt'),
    os.path.join(HOME_DIR, 'Pictures', 'fotos_viagem_secreta.zip'),
    os.path.join(HOME_DIR, 'Desktop', 'trabalho_faculdade.docx')
}

# --- FUNÇÕES DE DETECÇÃO E PROTEÇÃO ---

def calculate_entropy(data: bytes) -> float:
    """Calcula a Entropia de Shannon para um conjunto de dados."""
    if not data:
        return 0
    
    entropy = 0
    freq_dict = {}
    for byte in data:
        freq_dict[byte] = freq_dict.get(byte, 0) + 1

    data_len = len(data)
    for count in freq_dict.values():
        p_x = count / data_len
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
            
    return entropy

def check_ransom_note_filename(file_path: str) -> bool:
    filename = os.path.basename(file_path)
    pattern = re.compile(r'((DECRYPT|RECOVER|RESTORE|HELP|INSTRUCTIONS).*\.(txt|html|hta))|restore_files_.*\.txt', re.IGNORECASE)
    if pattern.match(filename):
        print(f"\n🚨 AMEAÇA DETECTADA (NOME DE ARQUIVO)! Arquivo suspeito: '{filename}'")
        return True
    return False

# ***** NOVA FUNÇÃO PARA DELETAR ARQUIVOS *****
def remover_arquivo_suspeito(file_path: str):
    """
    Tenta deletar permanentemente um arquivo identificado como malicioso.
    """
    print(f"[*] Ameaça confirmada. Tentando deletar o arquivo: {os.path.basename(file_path)}")
    try:
        os.remove(file_path)
        print(f"[+] Arquivo '{os.path.basename(file_path)}' deletado com sucesso.")
    except PermissionError:
        print(f"[-] Falha ao deletar: Permissão negada. O arquivo pode estar em uso.")
    except FileNotFoundError:
        print(f"[-] Falha ao deletar: Arquivo não encontrado (pode já ter sido removido).")
    except Exception as e:
        print(f"[-] Ocorreu um erro inesperado ao tentar deletar o arquivo: {e}")

def encerrar_proctree():
    global ult_processos, active_threat
    if active_threat:
        return
    
    active_threat = True
    print("\n" + "🚨 AMEAÇA DETECTADA! ACIONANDO PROTOCOLO DE MITIGAÇÃO! 🚨")
    pids_to_kill = ""
    for pid in reversed(ult_processos):
        if psutil.pid_exists(pid) and pid != os.getpid():
            pids_to_kill += f"/PID {pid} "
    
    if pids_to_kill:
        print(f"Encerrando processos suspeitos (PIDs): {pids_to_kill.replace('/PID', '').strip()}")
        subprocess.run(f"taskkill {pids_to_kill}/F /T", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    ult_processos.clear()
    print("Processos suspeitos encerrados. Recomenda-se reiniciar o sistema.")
    time.sleep(10) 
    active_threat = False

def avaliar_heuristica():
    global change_type
    criados, modificados, movidos, deletados, honeypot = change_type

    if honeypot > 0:
        print("\nHeurística: Modificação em arquivo honeypot (isca) detectada!")
        return True
    if modificados > 30 and criados > 10:
        print("\nHeurística: Alto volume de modificação e criação de arquivos!")
        return True
    if deletados > 50:
        print("\nHeurística: Alto volume de exclusão de arquivos!")
        return True
    return False

def extrair_extensao(file: str):
    extensions = [".exe", ".dll", ".com", ".bat", ".vbs", ".ps1"]
    file_extension = pathlib.Path(file).suffix
    return file_extension.lower() in extensions

def novos_processos():
    global ult_processos
    now = time.time()
    current_pids = []
    
    for process in psutil.process_iter(['pid', 'create_time', 'cmdline']):
        try:
            cmdline_list = process.info['cmdline']
            
            if cmdline_list:
                cmdline = " ".join(cmdline_list).lower()
            else:
                cmdline = ""

            if "vssadmin" in cmdline and "delete" in cmdline and "shadows" in cmdline:
                print(f"\n🚨 ALERTA MÁXIMO! Tentativa de exclusão de Cópias de Sombra detectada! (PID: {process.info['pid']})")
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

# --- CLASSE DE MONITORAMENTO ---
class MonitorFolder(FileSystemEventHandler):
    def __init__(self, yara_scanner: YaraScanner):
        self.yara_scanner = yara_scanner
        super().__init__()

    def _analyze_file(self, file_path, is_new_file=False):
        """Função centralizada para analisar um arquivo com múltiplas tentativas."""
        for attempt in range(3):
            try:
                if check_ransom_note_filename(file_path):
                    remover_arquivo_suspeito(file_path) # <<< DELETAR
                    encerrar_proctree()
                    return

                if self.yara_scanner.scan_file(file_path):
                    remover_arquivo_suspeito(file_path) # <<< DELETAR
                    encerrar_proctree()
                    return
                
                if is_new_file and extrair_extensao(file_path):
                    detector = DetectorMalware(file_path)
                    if detector.is_malware():
                        remover_arquivo_suspeito(file_path) # <<< DELETAR
                        encerrar_proctree()
                        return

                if not is_new_file:
                    with open(file_path, "rb") as f:
                        data = f.read()
                    entropy = calculate_entropy(data)
                    if entropy > 7.2:
                        print(f"\n🚨 ALERTA DE ENTROPIA! Arquivo '{file_path}' parece ter sido criptografado (Entropia: {entropy:.2f})")
                        # Neste caso, o arquivo já está criptografado, deletá-lo pode não ser o ideal.
                        # Vamos focar em parar o processo. Se quiser deletar, adicione a linha abaixo.
                        # remover_arquivo_suspeito(file_path) 
                        encerrar_proctree()
                        return
                break 

            except (IOError, PermissionError):
                print(f"\n[Aviso] Não foi possível acessar '{os.path.basename(file_path)}' na tentativa {attempt + 1}. Tentando novamente...")
                time.sleep(0.1)
            
            except Exception as e:
                print(f"\n[Erro Inesperado] Ocorreu um erro durante a análise de '{os.path.basename(file_path)}': {e}")
                break

    def on_any_event(self, event):
        global last_activity_time
        last_activity_time = time.time()
        if avaliar_heuristica():
            encerrar_proctree()
    
    def on_created(self, event):
        if event.is_directory: return
        change_type[0] += 1
        self._analyze_file(event.src_path, is_new_file=True)

    def on_deleted(self, event):
        if event.is_directory: return # Ignora eventos de diretório
        change_type[3] += 1

    def on_modified(self, event):
        if event.is_directory: return
        change_type[1] += 1

        if event.src_path in CANARY_FILES:
            print(f"\n🚨 ALERTA MÁXIMO! Arquivo isca '{os.path.basename(event.src_path)}' foi modificado!")
            # Não deletamos o arquivo isca, ele é nosso alarme
            encerrar_proctree()
            return
        
        self._analyze_file(event.src_path, is_new_file=False)

    def on_moved(self, event):
        change_type[2] += 1
        if event.src_path in CANARY_FILES or event.dest_path in CANARY_FILES:
            print(f"\n🚨 ALERTA MÁXIMO! Arquivo isca '{os.path.basename(event.src_path)}' foi movido/renomeado!")
            encerrar_proctree()
            return

# --- EXECUÇÃO PRINCIPAL ---
if __name__ == "__main__":
    print("Verificando arquivos isca (Canary Files)...")
    for f in CANARY_FILES:
        if not os.path.exists(f):
            try:
                pathlib.Path(os.path.dirname(f)).mkdir(parents=True, exist_ok=True)
                pathlib.Path(f).touch()
                print(f" -> Criado arquivo isca: {f}")
            except Exception as e:
                print(f" -> Erro ao criar arquivo isca {f}: {e}")

    scanner = YaraScanner()
    if scanner.rules is None:
        print("Não foi possível iniciar o monitoramento sem as regras YARA.")
        exit()

    paths_to_watch = [
        os.path.join(HOME_DIR, 'Downloads'),
        os.path.join(HOME_DIR, 'Documents'),
        os.path.join(HOME_DIR, 'Desktop'),
        os.path.join(HOME_DIR, 'Pictures'),
    ]

    event_handler = MonitorFolder(yara_scanner=scanner)
    observer = Observer()
    
    print("\nIniciando monitoramento...")
    for path in paths_to_watch:
        if os.path.exists(path):
            observer.schedule(event_handler, path=path, recursive=True)
            print(f" -> Monitorando: {path}")
        else:
            print(f" -> Aviso: O diretório '{path}' não existe e não será monitorado.")

    observer.start()
    
    spinner_states = ['-', '\\', '|', '/']
    spinner_index = 0
    
    try:
        while True:
            spinner_char = spinner_states[spinner_index]
            sys.stdout.write(f"\rMonitorando ativamente... {spinner_char}")
            sys.stdout.flush()
            spinner_index = (spinner_index + 1) % len(spinner_states)
            
            novos_processos()
            
            if time.time() - last_activity_time > 15:
                change_type = [0, 0, 0, 0, 0]

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\nMonitoramento encerrado pelo usuário.") 
        observer.stop()
    
    observer.join()
