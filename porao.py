# porao.py (ATUALIZADO)

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
import threading

class PoraoMonitor:
    def __init__(self, gui_update_callback=None):
        self.username = os.getlogin()
        self.ult_processos = []
        self.active_threat = False
        self.monitoring_active = True
        self.gui_update_callback = gui_update_callback

        self.threats_blocked = 0
        # --- REMOVIDO: A contagem de arquivos agora é feita em tempo real ---
        # self.files_monitored = 0 
        self.start_time = None
        
        self.HOME_DIR = os.path.expanduser('~')
        self.CANARY_FILES = {
            os.path.join(self.HOME_DIR, 'Documents', 'dados_bancarios.xlsx'),
            os.path.join(self.HOME_DIR, 'Desktop', 'trabalho_faculdade.docx')
        }
        self.QUARANTINE_DIR = os.path.join(self.HOME_DIR, "Quarantine")
        self.QUARANTINE_PASS = b"infected"
        self.paths_to_watch_global = []

        self.WHITELISTED_PROCESSES = {
            "svchost.exe", "runtimebroker.exe", "sihost.exe", "taskhostw.exe",
            "ctfmon.exe", "smartscreen.exe", "fontdrvhost.exe", "dwm.exe",
            "securityhealthservice.exe", "securityhealthsystray.exe",
            "searchapp.exe", "searchfilterhost.exe", "searchprotocolhost.exe",
            "shellexperiencehost.exe", "startmenuexperiencehost.exe",
            "trustedinstaller.exe", "tiworker.exe", "sppsvc.exe", "useroobebroker.exe",
            "backgroundtaskhost.exe", "applicationframehost.exe", "compattelrunner.exe",
            "textinputhost.exe", "systemsettings.exe", "wudfhost.exe", "conhost.exe",
            "poraoantiransomware.exe"
        }

    # --- NOVA FUNÇÃO: Conta todos os arquivos nos diretórios monitorados ---
    def update_total_file_count(self):
        count = 0
        # Usamos um conjunto para evitar contar o mesmo diretório duas vezes
        paths_to_scan = set(p for p in self.paths_to_watch_global if os.path.exists(p))
        
        for path in paths_to_scan:
            try:
                for _, _, files in os.walk(path):
                    count += len(files)
            except Exception as e:
                self.log(f"Aviso: Não foi possível acessar '{path}' para contagem de arquivos. Erro: {e}")

        self._send_update({'type': 'stat_update', 'stat': 'files_monitored', 'value': count})


    def _send_update(self, data):
        if self.gui_update_callback:
            self.gui_update_callback(data)

    def log(self, message):
        print(message)
        self._send_update({'type': 'log', 'message': message})

    def colocar_em_quarentena(self, file_path: str, reason: str):
        if not os.path.exists(file_path) or not os.path.isfile(file_path): return
        base_name = os.path.basename(file_path)
        if base_name.lower() in self.WHITELISTED_PROCESSES:
            self.log(f"[INFO] Ação em '{base_name}' ignorada (processo na whitelist).")
            return
        file_size = os.path.getsize(file_path)
        self.log(f"[*] Movendo para quarentena: {base_name} (Motivo: {reason})")
        try:
            os.makedirs(self.QUARANTINE_DIR, exist_ok=True)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            zip_name = f"{base_name}_{time.strftime('%Y%m%d-%H%M%S')}.zip"
            zip_path = os.path.join(self.QUARANTINE_DIR, zip_name)
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.setpassword(self.QUARANTINE_PASS)
                zf.write(file_path, arcname=base_name)
            os.remove(file_path)
            self.log(f"[+] Arquivo '{base_name}' movido para quarentena e protegido com senha.")
            quarantine_details = {
                'file_name': base_name,
                'reason': reason,
                'timestamp': timestamp,
                'size_kb': round(file_size / 1024, 2),
                'risk': 'critical' if reason in ['HASH', 'YARA', 'Executável de Origem'] else 'high'
            }
            self._send_update({'type': 'quarantine_add', 'details': quarantine_details})
        except Exception as e:
            self.log(f"[-] Falha ao mover para quarentena: {e}")

    def encerrar_proctree(self, reason="Ameaça Detectada"):
        if self.active_threat: return
        self.active_threat = True
        self.log("\n" + f"🚨 {reason.upper()}! ACIONANDO PROTOCOLO FOCO NA ORIGEM! 🚨")
        self.threats_blocked += 1
        self._send_update({'type': 'stat_update', 'stat': 'threats_blocked', 'value': self.threats_blocked})
        pids_to_kill = []
        executaveis_a_quarentenar = set()
        for pid in reversed(self.ult_processos):
            if psutil.pid_exists(pid):
                try:
                    processo = psutil.Process(pid)
                    exe_path = processo.exe()
                    if exe_path and os.path.exists(exe_path) and os.path.basename(exe_path).lower() not in self.WHITELISTED_PROCESSES:
                        pids_to_kill.append(pid)
                        executaveis_a_quarentenar.add(exe_path)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        if executaveis_a_quarentenar:
            self.log("[*] Neutralizando executáveis de origem...")
            for exe in executaveis_a_quarentenar:
                self.colocar_em_quarentena(exe, reason="Executável de Origem")
        meu_pid = os.getpid()
        pids_to_kill_str = " ".join([f"/PID {pid}" for pid in pids_to_kill if pid != meu_pid])
        if pids_to_kill_str:
            self.log(f"[*] Encerrando processos suspeitos (PIDs): {pids_to_kill_str.replace('/PID', '').strip()}")
            subprocess.run(f"taskkill {pids_to_kill_str} /F /T", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.ult_processos.clear()
        self.log("[+] Ameaça neutralizada. O monitoramento continua ativo.")
        time.sleep(5)
        self.active_threat = False

    def calculate_entropy(self, data: bytes) -> float:
        if not data: return 0
        entropy = 0; freq_dict = {}
        for byte in data: freq_dict[byte] = freq_dict.get(byte, 0) + 1
        data_len = len(data)
        for count in freq_dict.values():
            p_x = count / data_len
            if p_x > 0: entropy -= p_x * math.log2(p_x)
        return entropy

    def extrair_extensao(self, file: str):
        extensions = [".exe", ".dll", ".com", ".bat", ".vbs", ".ps1"]
        file_extension = pathlib.Path(file).suffix
        return file_extension.lower() in extensions

    def novos_processos(self):
        now = time.time()
        for process in psutil.process_iter(['pid', 'create_time', 'exe']):
            try:
                if (now - process.info['create_time']) < 120:
                    if process.info['pid'] not in self.ult_processos:
                        self.ult_processos.append(process.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    
    def start_monitoring(self):
        self.monitoring_active = True
        self.start_time = time.time()
        self.scanner = YaraScanner()
        if self.scanner.rules is None:
            self.log("[ERRO] Não foi possível carregar as regras YARA.")
            return
        self.paths_to_watch_global = [os.path.join(self.HOME_DIR, d) for d in ['Downloads', 'Documents', 'Desktop', 'Pictures']]
        temp_paths = [os.environ.get("TEMP"), os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp")]
        for path in temp_paths:
            if path and os.path.exists(path) and path not in self.paths_to_watch_global:
                self.paths_to_watch_global.append(path)
        event_handler = MonitorFolder(self)
        self.observer = Observer()
        self.log("\nIniciando monitoramento com Doutrina de Resposta Rápida...")
        for path in self.paths_to_watch_global:
            if os.path.exists(path):
                self.observer.schedule(event_handler, path=path, recursive=True)
                self.log(f" -> Monitorando: {path}")
            else:
                self.log(f" -> Aviso: O diretório '{path}' não existe.")
        self.observer.start()
        
        # --- ALTERADO: Loop principal agora atualiza a contagem de arquivos periodicamente ---
        last_file_count_update = 0
        try:
            while self.monitoring_active:
                now = time.time()
                self.novos_processos()
                self._send_update({'type': 'stat_update', 'stat': 'last_check', 'value': now})

                # Atualiza a contagem total de arquivos a cada 20 segundos para não pesar
                if now - last_file_count_update > 20:
                    self.update_total_file_count()
                    last_file_count_update = now

                time.sleep(2)
        except Exception as e:
            self.log(f"[ERRO CRÍTICO] Ocorreu um erro no loop de monitoramento: {e}")
        finally:
            self.observer.stop()
            self.observer.join()
            self.log("[INFO] Monitoramento interrompido.")

    def stop_monitoring(self):
        self.monitoring_active = False

class MonitorFolder(FileSystemEventHandler):
    def __init__(self, monitor_instance: PoraoMonitor):
        self.monitor = monitor_instance
        self.yara_scanner = monitor_instance.scanner
        super().__init__()
    
    # --- REMOVIDO: A função de contagem de eventos não é mais necessária ---
    # def _update_monitored_files_stat(self): ...

    def _analyze_file(self, file_path, is_new_file=False):
        try:
            if os.path.basename(file_path).lower() in self.monitor.WHITELISTED_PROCESSES:
                return
            
            # --- REMOVIDO: A chamada para a contagem de eventos ---
            # self._update_monitored_files_stat()

            if is_new_file and self.monitor.extrair_extensao(file_path):
                if self.yara_scanner.scan_file(file_path):
                    self.monitor.encerrar_proctree(reason="Ameaça YARA"); return
                detector = DetectorMalware(file_path)
                if detector.is_malware():
                    self.monitor.encerrar_proctree(reason="HASH de Malware"); return

            if not is_new_file and not self.monitor.extrair_extensao(file_path):
                with open(file_path, "rb") as f:
                    data = f.read()
                if self.monitor.calculate_entropy(data) > 7.2:
                    self.monitor.log(f"\n🚨 ALERTA DE ENTROPIA! Arquivo '{os.path.basename(file_path)}' suspeito de criptografia.")
                    self.monitor.encerrar_proctree(reason="Alta Entropia")
                    return
        except Exception:
            pass

    def on_created(self, event):
        if event.is_directory or self.monitor.active_threat: return
        self._analyze_file(event.src_path, is_new_file=True)

    def on_modified(self, event):
        if event.is_directory or self.monitor.active_threat: return
        if event.src_path in self.monitor.CANARY_FILES:
            self.monitor.log(f"\n🚨 ALERTA MÁXIMO! Arquivo isca '{os.path.basename(event.src_path)}' foi modificado!")
            self.monitor.encerrar_proctree(reason="Arquivo Isca Modificado")
            return
        self._analyze_file(event.src_path, is_new_file=False)

    def on_moved(self, event):
        if self.monitor.active_threat: return
        if event.src_path in self.monitor.CANARY_FILES or event.dest_path in self.monitor.CANARY_FILES:
            self.monitor.log(f"\n🚨 ALERTA MÁXIMO! Arquivo isca '{os.path.basename(event.src_path)}' foi movido/renomeado!")
            self.monitor.encerrar_proctree(reason="Arquivo Isca Movido")