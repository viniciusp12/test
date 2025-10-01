# porao.py (VERSÃO FINAL DE COMPATIBILIDADE - PSUTIL)

from detector import DetectorMalware
from yara_scanner import YaraScanner
from ml_scanner import MLScanner
import os
import pathlib
import psutil
import time
import subprocess
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import sys
import math
import zipfile

class PoraoMonitor:
    def __init__(self, gui_update_callback=None):
        self.username = os.getlogin()
        self.ult_processos_vistos = set()
        self.active_threat = False
        self.monitoring_active = True
        self.gui_update_callback = gui_update_callback
        self.threats_blocked = 0
        self.start_time = time.time()
        self.HOME_DIR = os.path.expanduser('~')
        self.CANARY_FILES = { os.path.join(self.HOME_DIR, 'Documents', 'dados_bancarios.xlsx'), os.path.join(self.HOME_DIR, 'Desktop', 'trabalho_faculdade.docx') }
        self.QUARANTINE_DIR = os.path.join(self.HOME_DIR, "Quarantine")
        self.QUARANTINE_PASS = b"infected"
        self.paths_to_watch_global = []
        self.WHITELISTED_PROCESSES = {
            "svchost.exe", "runtimebroker.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "smartscreen.exe", "fontdrvhost.exe", "dwm.exe",
            "securityhealthservice.exe", "securityhealthsystray.exe", "searchapp.exe", "searchfilterhost.exe", "searchprotocolhost.exe",
            "shellexperiencehost.exe", "startmenuexperiencehost.exe", "trustedinstaller.exe", "tiworker.exe", "sppsvc.exe", "useroobebroker.exe",
            "backgroundtaskhost.exe", "applicationframehost.exe", "compattelrunner.exe", "textinputhost.exe", "systemsettings.exe",
            "wudfhost.exe", "conhost.exe", "poraoantiransomware.exe", "explorer.exe", "dllhost.exe", "wmiprvse.exe", "audiodg.exe",
            "rundll32.exe", "msedge.exe", "spoolsv.exe", "consent.exe"
        }
        self.RANSOMWARE_EXTENSIONS = {
            ".encrypt", ".cry", ".crypto", ".darkness", ".enc", ".exx", ".kb15", ".kraken", ".locked", ".nochance", "._AiraCropEncrypted",
            ".aaa", ".abc", ".AES", ".alcatraz", ".amnesia", ".cerber", ".cerber2", ".cerber3", ".crypted", ".cryptoLocker", ".crjoker",
            ".crptrgr", ".cryp1", ".crypt", ".crypt38", ".cryptowall", ".crysis", ".dharma", ".diablo6", ".enCiPhErEd", ".fantom",
            ".globe", ".java", ".jb-ne", ".karma", ".korrektor", ".LeChiffre", ".locky", ".malki", ".merry", ".nalog@qq_com", ".odin",
            ".oops", ".osiris", ".purge", ".r5a", ".RARE1", ".rokku", ".sage", ".shit", ".silent", ".thor", ".troyancoder@qq_com",
            ".unavailable", ".vault", ".vvv", ".wcry", ".WNCRY", ".wncryt", ".wnry", ".xdata", ".xtbl", ".xyz", ".zcrypt", ".zepto", ".zorro", ".zzzzz"
        }
        self.entropy_hit_score = 0
        self.last_entropy_hit_time = 0

    def _send_update(self, data):
        if self.gui_update_callback: self.gui_update_callback(data)
    def log(self, message):
        print(message); self._send_update({'type': 'log', 'message': message})
    def colocar_em_quarentena(self, file_path: str, reason: str):
        if not os.path.exists(file_path) or not os.path.isfile(file_path): return
        base_name = os.path.basename(file_path)
        if base_name.lower() in self.WHITELISTED_PROCESSES: return
        try:
            os.makedirs(self.QUARANTINE_DIR, exist_ok=True)
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            zip_name = f"{base_name}_{time.strftime('%Y%m%d-%H%M%S')}.zip"
            zip_path = os.path.join(self.QUARANTINE_DIR, zip_name)
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.setpassword(self.QUARANTINE_PASS); zf.write(file_path, arcname=base_name)
            os.remove(file_path)
            self.log(f"[+] Arquivo '{base_name}' movido para quarentena.")
            quarantine_details = {'file_name': base_name, 'reason': reason, 'timestamp': timestamp, 'size_kb': round(os.path.getsize(zip_path) / 1024, 2), 'risk': 'critical'}
            self._send_update({'type': 'quarantine_add', 'details': quarantine_details})
        except Exception as e:
            self.log(f"[-] Falha ao mover '{base_name}' para quarentena: {e}")
    def encerrar_proctree(self, reason="Ameaça Detectada", pid=None):
        if self.active_threat: return
        self.active_threat = True
        self.log("\n" + f"🚨 AMEAÇA DE ALTA CONFIANÇA DETECTADA ({reason.upper()})! ACIONANDO PROTOCOLO! 🚨")
        self.threats_blocked += 1
        self._send_update({'type': 'stat_update', 'stat': 'threats_blocked', 'value': self.threats_blocked})
        pids_to_kill = set()
        executaveis_a_quarentenar = set()
        if pid: pids_to_kill.add(pid)
        # Usa a lista de processos recentes do psutil
        for p in self.ult_processos_vistos:
            if psutil.pid_exists(p): pids_to_kill.add(p)
        for pid_to_check in list(pids_to_kill):
            try:
                processo = psutil.Process(pid_to_check)
                exe_path = processo.exe()
                if exe_path and os.path.exists(exe_path) and os.path.basename(exe_path).lower() not in self.WHITELISTED_PROCESSES:
                    executaveis_a_quarentenar.add(exe_path)
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        if executaveis_a_quarentenar:
            self.log("[*] Neutralizando executáveis de origem...")
            for exe in executaveis_a_quarentenar: self.colocar_em_quarentena(exe, reason="Executável de Origem")
        meu_pid = os.getpid()
        pids_to_kill_str = " ".join([f"/PID {p}" for p in pids_to_kill if p != meu_pid])
        if pids_to_kill_str:
            self.log(f"[*] Encerrando processos suspeitos (PIDs): {pids_to_kill_str.replace('/PID', '').strip()}")
            subprocess.run(f"taskkill {pids_to_kill_str} /F /T", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.ult_processos_vistos.clear()
        self.log("[+] Ameaça neutralizada. O sistema está seguro.")
        time.sleep(2)
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
        return pathlib.Path(file).suffix.lower() in extensions
    
    def check_new_processes(self):
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
            try:
                if proc.pid in self.ult_processos_vistos: continue
                if (time.time() - proc.info['create_time']) < 5:
                    self.ult_processos_vistos.add(proc.pid)
                    proc_path = proc.info['exe']
                    proc_name = proc.info['name']
                    if not proc_path or proc_name.lower() in self.WHITELISTED_PROCESSES: continue
                    self.log(f"[Processo Detectado] '{proc_name}' (PID: {proc.pid})")
                    if self.extrair_extensao(proc_path):
                        if self.ml_scanner.is_malware(proc_path):
                            self.encerrar_proctree(reason="Ameaça Detectada por ML", pid=proc.pid); return
                        if self.scanner.scan_file(proc_path):
                            self.encerrar_proctree(reason="Ameaça YARA", pid=proc.pid); return
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def start_monitoring(self):
        self.monitoring_active = True
        self.scanner = YaraScanner()
        self.ml_scanner = MLScanner()
        watchdog_thread = threading.Thread(target=self.start_watchdog_monitor, daemon=True)
        watchdog_thread.start()
        self.log("\nIniciando monitoramento de processos (Modo de Compatibilidade)...")
        for proc in psutil.process_iter(['pid']): self.ult_processos_vistos.add(proc.pid)
        while self.monitoring_active:
            self.check_new_processes()
            time.sleep(0.1)

    def start_watchdog_monitor(self):
        self.paths_to_watch_global = [os.path.join(self.HOME_DIR, d) for d in ['Downloads', 'Documents', 'Desktop', 'Pictures']]
        temp_paths = [os.environ.get("TEMP"), os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp")]
        for path in temp_paths:
            if path and os.path.exists(path) and path not in self.paths_to_watch_global: self.paths_to_watch_global.append(path)
        event_handler = MonitorFolder(self)
        observer = Observer()
        self.log("\nIniciando monitoramento de arquivos (Watchdog)...")
        for path in self.paths_to_watch_global:
            if os.path.exists(path): observer.schedule(event_handler, path=path, recursive=True)
        observer.start(); observer.join()
    
    def stop_monitoring(self):
        self.monitoring_active = False

class MonitorFolder(FileSystemEventHandler):
    def __init__(self, monitor_instance: PoraoMonitor):
        self.monitor = monitor_instance
        self.yara_scanner = monitor_instance.scanner
        self.ml_scanner = monitor_instance.ml_scanner
        super().__init__()
    def _check_hash_in_background(self, file_path):
        detector = DetectorMalware(file_path)
        if detector.is_malware():
            self.monitor.log(f"Análise em 2º plano detectou HASH malicioso em '{os.path.basename(file_path)}'.")
            self.monitor.colocar_em_quarentena(file_path, reason="HASH de Malware (2º Plano)")
    def _analyze_file(self, file_path, event_type):
        try:
            filename = os.path.basename(file_path)
            if filename.lower() in self.monitor.WHITELISTED_PROCESSES: return
            file_ext = pathlib.Path(filename).suffix.lower()
            if file_ext in self.monitor.RANSOMWARE_EXTENSIONS:
                self.monitor.log(f"\n🚨 ALERTA MÁXIMO! DETECTADA EXTENSÃO DE RANSOMWARE '{file_ext}' EM '{filename}'!")
                self.monitor.encerrar_proctree(reason=f"Extensão Maliciosa ({file_ext})"); return
            if event_type == 'created' and self.monitor.extrair_extensao(file_path):
                # A análise de ML/YARA agora é feita pelo loop principal do psutil
                pass
            if event_type == 'modified' and not self.monitor.extrair_extensao(file_path):
                with open(file_path, "rb") as f: data = f.read(524288) 
                if self.monitor.calculate_entropy(data) > 7.2:
                    now = time.time()
                    if now - self.monitor.last_entropy_hit_time > 3: self.monitor.entropy_hit_score = 0
                    self.monitor.entropy_hit_score += 1
                    self.monitor.last_entropy_hit_time = now
                    self.monitor.log(f"[*] ALERTA DE ENTROPIA! Arquivo '{filename}' suspeito. Nível de Agressividade: {self.monitor.entropy_hit_score}/5")
                    if self.monitor.entropy_hit_score >= 5:
                        self.monitor.log(f"\n🚨 PADRÃO DE ATAQUE DETECTADO! MÚLTIPLOS ALERTAS DE ENTROPIA EM SÉRIE!")
                        self.monitor.encerrar_proctree(reason="Padrão de Criptografia Rápida"); return
        except Exception: pass
    def on_created(self, event):
        if event.is_directory or self.monitor.active_threat: return
        self._analyze_file(event.src_path, event_type='created')
    def on_modified(self, event):
        if event.is_directory or self.monitor.active_threat: return
        if event.src_path in self.monitor.CANARY_FILES:
            self.monitor.log(f"\n🚨 ALERTA MÁXIMO! GATILHO ISCA ACIONADO EM '{os.path.basename(event.src_path)}'!")
            self.monitor.encerrar_proctree(reason="Arquivo Isca Modificado"); return
        self._analyze_file(event.src_path, event_type='modified')
    def on_moved(self, event):
        if event.is_directory or self.monitor.active_threat: return
        if event.src_path in self.monitor.CANARY_FILES or event.dest_path in self.monitor.CANARY_FILES:
            self.monitor.log(f"\n🚨 ALERTA MÁXIMO! GATILHO ISCA MOVIDO/RENOMEADO!")
            self.monitor.encerrar_proctree(reason="Arquivo Isca Movido"); return
        self._analyze_file(event.dest_path, event_type='moved')