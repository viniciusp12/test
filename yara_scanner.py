# yara_scanner.py

import yara
import os

class YaraScanner:
    def __init__(self):
        """
        Compila as regras YARA a partir de um arquivo de índice externo.
        """
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            rules_path = os.path.join(base_dir, "rules", "index.yar")

            print("Compilando regras YARA a partir de:", rules_path)
            
            if not os.path.exists(rules_path):
                print(f"Erro: Arquivo de índice YARA não encontrado em '{rules_path}'")
                print("Por favor, crie a pasta 'rules' e o arquivo 'index.yar' conforme as instruções.")
                self.rules = None
                return

            self.rules = yara.compile(filepath=rules_path)
            print("Regras YARA compiladas com sucesso.")

        except yara.Error as e:
            print(f"Erro ao compilar regras YARA: {e}")
            self.rules = None

    def scan_file(self, file_path: str) -> bool:
        """
        Escaneia o CONTEÚDO de um único arquivo com as regras YARA compiladas.
        """
        if not self.rules or not os.path.exists(file_path):
            return False
        
        try:
            matches = self.rules.match(filepath=file_path, timeout=5)
            
            if matches:
                matched_rules = list(set([match.rule for match in matches]))
                print(f"🚨 AMEAÇA YARA DETECTADA! Arquivo: '{os.path.basename(file_path)}'. Regra(s): {matched_rules}")
                return True
        except yara.TimeoutError:
            print(f"[Aviso] Verificação YARA do arquivo '{os.path.basename(file_path)}' excedeu o tempo limite.")
            return False
        except yara.Error:
            return False
        
        return False