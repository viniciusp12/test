# ml_scanner.py

import os
import pickle
import joblib
import pefile
import array
import math

class MLScanner:
    def __init__(self):
        self.clf = None
        self.features = None
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            classifier_path = os.path.join(base_dir, "classifier", "svm_classifier.pkl")
            features_path = os.path.join(base_dir, "classifier", "svm_features.pkl")
            if not os.path.exists(classifier_path) or not os.path.exists(features_path):
                print("[ERRO ML] Arquivos de modelo (.pkl) não encontrados na pasta 'classifier'.")
                return
            print("[INFO ML] Carregando modelo de Machine Learning...")
            self.clf = joblib.load(classifier_path)
            with open(features_path, 'rb') as f:
                self.features = pickle.load(f)
            print("[INFO ML] Modelo carregado com sucesso.")
        except Exception as e:
            print(f"[ERRO ML] Falha ao carregar o modelo de Machine Learning: {e}")

    def is_malware(self, file_path: str) -> bool:
        if not self.clf or not self.features or not os.path.exists(file_path):
            return False
        try:
            print(f"[INFO ML] Analisando '{os.path.basename(file_path)}' com ML...")
            data = self._extract_infos(file_path)
            if not data:
                return False
            pe_features = [data.get(feature, 0) for feature in self.features]
            prediction = self.clf.predict([pe_features])[0]
            if prediction == 0:
                print(f"🚨 AMEAÇA ML DETECTADA! Arquivo: '{os.path.basename(file_path)}' classificado como MALICIOSO.")
                return True
        except pefile.PEFormatError:
            return False
        except Exception as e:
            print(f"[ERRO ML] Falha durante a análise do arquivo '{os.path.basename(file_path)}': {e}")
            return False
        return False

    def _get_entropy(self, data):
        if len(data) == 0: return 0.0
        occurences = array.array('L', [0] * 256)
        for x in data: occurences[x if isinstance(x, int) else ord(x)] += 1
        entropy = 0
        for x in occurences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x * math.log(p_x, 2)
        return entropy

    def _get_resources(self, pe):
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    size = resource_lang.data.struct.Size
                                    entropy = self._get_entropy(data)
                                    resources.append([entropy, size])
            except Exception:
                return resources
        return resources

    def _extract_infos(self, fpath):
        res = {}; pe = None
        try:
            pe = pefile.PE(fpath)
            res['Machine'] = pe.FILE_HEADER.Machine
            res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
            res['Characteristics'] = pe.FILE_HEADER.Characteristics
            res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
            res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
            res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
            res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
            res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
            res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
            try: res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
            except AttributeError: res['BaseOfData'] = 0
            res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
            res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
            res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
            res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
            res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
            res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
            res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
            res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
            res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
            res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
            res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
            res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
            res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
            res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
            res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
            res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
            res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
            res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
            res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            res['SectionsNb'] = len(pe.sections)
            entropy = [s.get_entropy() for s in pe.sections]
            res['SectionsMeanEntropy'] = sum(entropy) / len(entropy)
            res['SectionsMinEntropy'] = min(entropy)
            res['SectionsMaxEntropy'] = max(entropy)
            try: res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            except AttributeError: res['ImportsNbDLL'] = 0
            try: res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            except AttributeError: res['ExportNb'] = 0
            resources = self._get_resources(pe)
            res['ResourcesNb'] = len(resources)
            if resources:
                entropy = [r[0] for r in resources]
                res['ResourcesMeanEntropy'] = sum(entropy) / len(entropy)
                res['ResourcesMinEntropy'] = min(entropy)
                res['ResourcesMaxEntropy'] = max(entropy)
            else:
                res['ResourcesMeanEntropy'], res['ResourcesMinEntropy'], res['ResourcesMaxEntropy'] = 0, 0, 0
            try: res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
            except AttributeError: res['LoadConfigurationSize'] = 0
        except Exception:
            return None
        finally:
            if pe: pe.close()
        return res