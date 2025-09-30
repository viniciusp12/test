# porao.py (ESTRATÉGIA INTELIGENTE E ESTÁVEL)

from detector import DetectorMalware
from yara_scanner import YaraScanner
import os
import pathlib
import psutil
import time
import subprocess
import threading # Importado para análise em segundo plano
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import sys
import math
import zipfile

class PoraoMonitor:
    def __init__(self, gui_update_callback=None):
        self.username = os.getlogin()
        self.ult_processos = []
        self.active_threat = False
        self.monitoring_active = True
        self.gui_update_callback = gui_update_callback
        self.threats_blocked = 0
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
            "poraoantiransomware.exe", "explorer.exe", "dllhost.exe", "wmiprvse.exe",
            "audiodg.exe", "rundll32.exe", "msedge.exe", "spoolsv.exe"
        }
        self.SNAPSHOT_ARQUIVOS = {}

    # As funções de snapshot serão mantidas, mas desativadas do gatilho principal por segurança.
    def criar_snapshot_arquivos(self):
        # ... (código mantido, mas não será chamado de forma destrutiva)
        pass

    def analisar_diferenca_e_agir(self):
        # ... (código mantido, mas não será chamado de forma destrutiva)
        pass

    def update_total_file_count(self):
        count = 0
        paths_to_scan = set(p for p in self.paths_to_watch_global if os.path.exists(p))
        for path in paths_to_scan:
            try:
                for _, _, files in os.walk(path):
                    count += len(files)
            except Exception: pass
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
        if base_name.lower() in self.WHITELISTED_PROCESSES: return
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
            self.log(f"[+] Arquivo '{base_name}' movido para quarentena.")
            quarantine_details = {'file_name': base_name, 'reason': reason, 'timestamp': timestamp, 'size_kb': round(file_size / 1024, 2), 'risk': 'critical'}
            self._send_update({'type': 'quarantine_add', 'details': quarantine_details})
        except Exception as e:
            self.log(f"[-] Falha ao mover '{base_name}' para quarentena: {e}")

    def encerrar_proctree(self, reason="Ameaça Detectada"):
        if self.active_threat: return
        self.active_threat = True
        self.log("\n" + f"🚨 AMEAÇA DE ALTA CONFIANÇA DETECTADA ({reason.upper()})! ACIONANDO PROTOCOLO! 🚨")
        self.threats_blocked += 1
        self._send_update({'type': 'stat_update', 'stat': 'threats_blocked', 'value': self.threats_blocked})
        
        # --- ALTERAÇÃO: A chamada para o snapshot destrutivo foi REMOVIDA daqui ---
        # self.analisar_diferenca_e_agir()

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
                except (psutil.NoSuchProcess, psutil.AccessDenied): continue
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
        file_extension = pathlib.Path(file).suffix
        return file_extension.lower() in extensions

    def novos_processos(self):
        now = time.time()
        for process in psutil.process_iter(['pid', 'create_time', 'exe']):
            try:
                if (now - process.info['create_time']) < 120:
                    if process.info['pid'] not in self.ult_processos:
                        self.ult_processos.append(process.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue
    
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
        self.log("\nIniciando monitoramento com Estratégia Inteligente...")
        for path in self.paths_to_watch_global:
            if os.path.exists(path):
                self.observer.schedule(event_handler, path=path, recursive=True)
                self.log(f" -> Monitorando: {path}")
            else:
                self.log(f" -> Aviso: O diretório '{path}' não existe.")
        self.observer.start()
        
        last_file_count_update = 0
        try:
            while self.monitoring_active:
                now = time.time()
                self.novos_processos()
                self._send_update({'type': 'stat_update', 'stat': 'last_check', 'value': now})
                if now - last_file_count_update > 20:
                    self.update_total_file_count()
                    last_file_count_update = now
                
                # --- ALTERAÇÃO: Retornando a um tempo de espera balanceado ---
                time.sleep(1) 
        except Exception as e:
            self.log(f"[ERRO CRÍTICO] Ocorreu um erro no loop: {e}")
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
    
    # --- NOVO: Função para rodar a análise de hash em segundo plano ---
    def _check_hash_in_background(self, file_path):
        detector = DetectorMalware(file_path)
        if detector.is_malware():
            self.monitor.log(f"Análise em 2º plano detectou HASH malicioso em '{os.path.basename(file_path)}'.")
            # A ação aqui é mais branda: apenas coloca o arquivo em quarentena, não encerra tudo.
            self.monitor.colocar_em_quarentena(file_path, reason="HASH de Malware (2º Plano)")

    def _analyze_file(self, file_path, is_new_file=False):
        try:
            if os.path.basename(file_path).lower() in self.monitor.WHITELISTED_PROCESSES:
                return
            
            # Análises rápidas que podem acionar o protocolo de extermínio
            if is_new_file and self.monitor.extrair_extensao(file_path):
                if self.yara_scanner.scan_file(file_path):
                    self.monitor.encerrar_proctree(reason="Ameaça YARA"); return
                
                # --- ALTERAÇÃO: A análise de hash agora roda em uma thread separada ---
                # Isso impede que a verificação online (lenta) trave a resposta imediata.
                threading.Thread(target=self._check_hash_in_background, args=(file_path,), daemon=True).start()

            if not is_new_file and not self.monitor.extrair_extensao(file_path):
                with open(file_path, "rb") as f:
                    data = f.read()
                if self.monitor.calculate_entropy(data) > 7.2:
                    self.monitor.log(f"\n🚨 ALERTA DE ENTROPIA! Arquivo '{os.path.basename(file_path)}' suspeito.")
                    # Ação de entropia é forte, mas vamos apenas quarentenar o arquivo específico, não tudo.
                    self.monitor.colocar_em_quarentena(file_path, "Alta Entropia")
                    return
        except Exception: pass

    def on_created(self, event):
        if event.is_directory or self.monitor.active_threat: return
        self._analyze_file(event.src_path, is_new_file=True)

    def on_modified(self, event):
        if event.is_directory or self.monitor.active_threat: return
        # A modificação de um arquivo isca é o nosso gatilho MAIS FORTE. Ação máxima aqui.
        if event.src_path in self.monitor.CANARY_FILES:
            self.monitor.log(f"\n🚨 ALERTA MÁXIMO! GATILHO ISCA ACIONADO EM '{os.path.basename(event.src_path)}'!")
            self.monitor.encerrar_proctree(reason="Arquivo Isca Modificado")
            return
        self._analyze_file(event.src_path, is_new_file=False)

    def on_moved(self, event):
        if self.monitor.active_threat: return
        if event.src_path in self.monitor.CANARY_FILES or event.dest_path in self.monitor.CANARY_FILES:
            self.monitor.log(f"\n🚨 ALERTA MÁXIMO! GATILHO ISCA MOVIDO/RENOMEADO!")
            self.monitor.encerrar_proctree(reason="Arquivo Isca Movido")