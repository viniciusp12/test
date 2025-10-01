# detector.py

import requests
import hashlib

class DetectorMalware:
    def __init__(self, last_file: str):
        self.last_file = last_file
        self.malware_info = {}

    def _gerar_hash(self):
        sha256 = hashlib.sha256()
        try:
            with open(self.last_file, "rb") as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, PermissionError):
            return None

    def is_malware(self) -> bool:
        file_hash = self._gerar_hash()
        if not file_hash:
            return False

        data = {"query": "get_info", "hash": file_hash}
        url = "https://mb-api.abuse.ch/api/v1/"
        
        try:
            response = requests.post(url, data=data, timeout=5).json()
            if response.get("query_status") == 'ok' and response.get('data'):
                info = response['data'][0]
                self.malware_info["signature"] = info.get("signature", "N/A")
                self.malware_info["sha256"] = info.get("sha256_hash", "N/A")
                print(f'\n🚨 MALWARE DETECTADO (HASH)! Signature: {self.malware_info["signature"]}')
                return True
        except (requests.RequestException, KeyError, IndexError):
            pass # Ignora erros de rede ou de formato de resposta
        return False