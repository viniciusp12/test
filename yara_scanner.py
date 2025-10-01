# yara_scanner.py

import yara
import os

class YaraScanner:
    def __init__(self):
        try:
            base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
            rules_path = os.path.join(base_dir, "rules", "index.yar")
            if not os.path.exists(rules_path):
                print(f"Erro: Arquivo de índice YARA não encontrado em '{rules_path}'")
                self.rules = None
                return
            self.rules = yara.compile(filepath=rules_path)
        except yara.Error as e:
            print(f"Erro ao compilar regras YARA: {e}")
            self.rules = None

    def scan_file(self, file_path: str) -> bool:
        if not self.rules or not os.path.exists(file_path):
            return False
        try:
            matches = self.rules.match(filepath=file_path, timeout=5)
            if matches:
                matched_rules = list(set(match.rule for match in matches))
                print(f"🚨 AMEAÇA YARA DETECTADA! Arquivo: '{os.path.basename(file_path)}'. Regra(s): {matched_rules}")
                return True
        except (yara.TimeoutError, yara.Error):
            return False
        return False