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
last_activity_time = time.time()
active_threat = False

# ***** NOVO: SISTEMA DE SNAPSHOT *****
SNAPSHOT_ARQUIVOS = {} # Dicionário para guardar o estado dos arquivos

HOME_DIR = os.path.expanduser('~')
CANARY_FILES = {
    os.path.join(HOME_DIR, 'Documents', 'dados_bancarios.xlsx'),
    os.path.join(HOME_DIR, 'Desktop', 'trabalho_faculdade.docx')
}
QUARANTINE_DIR = os.path.join(HOME_DIR, "Quarantine")
QUARANTINE_PASS = b"infected"

FORBIDDEN_EXEC_PATHS = [
    os.environ.get("TEMP", "").lower(),
    os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp").lower()
]
FORBIDDEN_EXEC_PATHS = [path for path in FORBIDDEN_EXEC_PATHS if path]

# --- FUNÇÕES DE DETECÇÃO E PROTEÇÃO ---

# ***** NOVO: FUNÇÃO PARA CRIAR SNAPSHOT *****
def criar_snapshot_arquivos(paths_to_watch):
    global SNAPSHOT_ARQUIVOS
    print("\n[*] Criando novo snapshot do sistema de arquivos...")
    temp_snapshot = {}
    for path in paths_to_watch:
        for root, _, files in os.walk(path):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    # Guarda o tempo da última modificação do arquivo
                    temp_snapshot[file_path] = os.path.getmtime(file_path)
                except (FileNotFoundError, PermissionError):
                    continue
    SNAPSHOT_ARQUIVOS = temp_snapshot
    print(f"[+] Snapshot criado com {len(SNAPSHOT_ARQUIVOS)} arquivos.")

# ***** NOVO: FUNÇÃO PARA COMPARAR SNAPSHOT E AGIR *****
def analisar_diferenca_e_agir(paths_to_watch):
    global SNAPSHOT_ARQUIVOS
    print("\n[*] Comparando estado atual com o último snapshot...")
    arquivos_afetados = 0
    for path in paths_to_watch:
        for root, _, files in os.walk(path):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    file_mtime = os.path.getmtime(file_path)
                    
                    # Verifica se o arquivo é novo (não estava no snapshot)
                    if file_path not in SNAPSHOT_ARQUIVOS:
                        print(f"[!] Novo arquivo suspeito detectado: {os.path.basename(file_path)}")
                        colocar_em_quarentena(file_path)
                        arquivos_afetados += 1
                    # Verifica se o arquivo foi modificado (tempo de modificação mudou)
                    elif file_mtime > SNAPSHOT_ARQUIVOS[file_path]:
                        print(f"[!] Arquivo modificado suspeito detectado: {os.path.basename(file_path)}")
                        colocar_em_quarentena(file_path)
                        arquivos_afetados += 1

                except (FileNotFoundError, PermissionError):
                    continue
    print(f"[+] Análise de snapshot concluída. {arquivos_afetados} arquivos foram movidos para a quarentena.")


def encerrar_proctree():
    global ult_processos, active_threat, paths_to_watch_global # Usaremos a lista global
    if active_threat: return
    active_threat = True
    print("\n" + "🚨 AMEAÇA DETECTADA! ACIONANDO PROTOCOLO DE MITIGAÇÃO! 🚨")
    
    # ***** LÓGICA PRINCIPAL DA SUA IDEIA *****
    # 1. Analisa a diferença entre o agora e o snapshot, e coloca tudo que for novo/modificado em quarentena.
    analisar_diferenca_e_agir(paths_to_watch_global)
    
    # 2. Encerra os processos suspeitos
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
    time.sleep(10) # Pausa para o sistema se estabilizar
    
    # 3. Cria um novo snapshot limpo após a mitigação
    criar_snapshot_arquivos(paths_to_watch_global)
    
    active_threat = False

# (O resto das funções como colocar_em_quarentena, novos_processos, etc., permanecem as mesmas)
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

def novos_processos():
    global ult_processos
    now = time.time()
    current_pids = []
    for process in psutil.process_iter(['pid', 'create_time', 'cmdline', 'exe']):
        try:
            exe_path = process.info.get('exe')
            if exe_path:
                for forbidden_path in FORBIDDEN_EXEC_PATHS:
                    if exe_path.lower().startswith(forbidden_path):
                        print(f"\n🚨 ALERTA PREVENTIVO! Processo suspeito executando de pasta temporária: {exe_path}")
                        if process.info['pid'] not in ult_processos: ult_processos.append(process.info['pid'])
                        encerrar_proctree()
                        return
            cmdline_list = process.info['cmdline']
            cmdline = " ".join(cmdline_list).lower() if cmdline_list else ""
            if "vssadmin" in cmdline and "delete" in cmdline and "shadows" in cmdline:
                if process.info['pid'] not in ult_processos: ult_processos.append(process.info['pid'])
                encerrar_proctree()
                return
            if (now - process.info['create_time']) < 120:
                if process.info['pid'] not in ult_processos: ult_processos.append(process.info['pid'])
                current_pids.append(process.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    ult_processos = [pid for pid in ult_processos if pid in current_pids]

# A classe MonitorFolder e suas funções não precisam mais existir,
# pois a nova lógica de snapshot é mais poderosa e centralizada.
# Vamos simplificar o código removendo a classe inteira.

# --- EXECUÇÃO PRINCIPAL ---
if __name__ == "__main__":
    global paths_to_watch_global # Definimos a lista de pastas globalmente
    
    paths_to_watch_global = [os.path.join(HOME_DIR, d) for d in ['Downloads', 'Documents', 'Desktop', 'Pictures']]
    temp_paths = [os.environ.get("TEMP"), os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp")]
    for path in temp_paths:
        if path and os.path.exists(path) and path not in paths_to_watch_global:
            paths_to_watch_global.append(path)

    # Cria o snapshot inicial
    criar_snapshot_arquivos(paths_to_watch_global)

    # A lógica de watchdog não é mais necessária, pois a verificação de processos é mais proativa
    # e a análise de snapshot é a nossa resposta reativa.
    
    print("\nIniciando monitoramento proativo de processos...")
    
    spinner_states = ['-', '\\', '|', '/']
    spinner_index = 0
    
    try:
        while True:
            spinner_char = spinner_states[spinner_index]
            sys.stdout.write(f"\rMonitorando ativamente... {spinner_char}"); sys.stdout.flush()
            spinner_index = (spinner_index + 1) % len(spinner_states)
            
            # A única tarefa agora é procurar por processos suspeitos.
            # A detecção de arquivos será feita pelo snapshot após um incidente.
            novos_processos()
            
            # Atualiza o snapshot se o sistema estiver inativo por 15 segundos
            if not active_threat and (time.time() - last_activity_time > 15):
                criar_snapshot_arquivos(paths_to_watch_global)
                last_activity_time = time.time() # Reseta o timer

            time.sleep(0.05)

    except KeyboardInterrupt:
        print("\nMonitoramento encerrado pelo usuário.")