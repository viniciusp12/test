# Porão Anti-Ransomware

🛡️ **Uma ferramenta robusta de defesa contra ransomware para ambientes Windows**

O **Porão Anti-Ransomware** é uma solução de segurança desenvolvida em Python, projetada para proteger sistemas Windows contra ataques de ransomware por meio de uma abordagem de **Defesa em Profundidade Híbrida**. A ferramenta combina vigilância proativa para identificar ameaças antes que elas atuem e detecção reativa para responder instantaneamente a atividades suspeitas no sistema de arquivos.

---

## 📖 Sobre o Projeto

O Porão Anti-Ransomware utiliza técnicas avançadas, como monitoramento de processos, análise de entropia, verificação de hashes em bancos de dados de malware, regras YARA e arquivos "isca" (canary files) para oferecer uma proteção multicamadas contra ransomwares. A ferramenta é acompanhada por uma interface gráfica intuitiva, construída com CustomTkinter, que exibe estatísticas em tempo real, logs de atividades e arquivos em quarentena.

### ✨ Principais Funcionalidades

- **Monitoramento Proativo**: Utiliza a biblioteca `psutil` para monitorar processos recém-criados em alta frequência (20 vezes por segundo), neutralizando ameaças no "segundo zero".
- **Detecção Reativa**: Emprega a biblioteca `watchdog` para reagir a eventos de sistema de arquivos (criação, modificação, exclusão) em tempo real.
- **Análise de Entropia**: Calcula a entropia de arquivos modificados para detectar padrões de criptografia, um forte indicativo de ransomware.
- **Verificação de Hash (Malware DB)**: Gera hashes SHA256 de executáveis e consulta a API do MalwareBazaar para identificar malwares conhecidos.
- **Scanner YARA**: Escaneia arquivos com regras YARA personalizadas para detectar famílias de malware e padrões maliciosos.
- **Arquivos "Isca" (Canary Files)**: Protege arquivos estratégicos que, ao serem modificados, acionam alertas e neutralizam ameaças imediatamente.
- **Quarentena Segura**: Isola arquivos maliciosos e seus executáveis em um diretório protegido por senha.
- **Interface Gráfica**: Interface moderna com CustomTkinter, exibindo estatísticas, logs e arquivos em quarentena.

---

## 🛠️ Tecnologias Utilizadas

- **Linguagem**: Python 3.8+
- **Interface Gráfica**: CustomTkinter
- **Monitoramento de Processos**: `psutil`
- **Monitoramento de Arquivos**: `watchdog`
- **Análise de Malware**: `yara-python`, `requests`
- **Manipulação de Strings**: `regex`

---

## 📦 Pré-requisitos

- **Sistema Operacional**: Windows 10 ou superior
- **Python**: 3.8+ (adicionado ao PATH do sistema)
- **Permissões**: Necessário executar com privilégios de Administrador

---

## 📥 Instalação

1. **Clone o repositório** (ou baixe o ZIP e extraia os arquivos):
   ```bash
   git clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
   cd SEU_REPOSITORIO
   ```

2. **Crie a pasta de regras YARA**:
   Na pasta do projeto, crie uma subpasta chamada `rules`:
   ```bash
   mkdir rules
   ```

3. **Adicione as regras YARA**:
   - Baixe arquivos de regras `.yar` de repositórios confiáveis (como [signature-base](https://github.com/Neo23x0/signature-base)).
   - Crie um arquivo `rules/index.yar` com as inclusões das regras baixadas. Exemplo:
     ```yara
     include "GEN_Ransomware.yar"
     include "Crime_Generic.yar"
     ```

4. **Instale as dependências**:
   Execute o comando abaixo no terminal:
   ```bash
   pip install psutil yara-python requests watchdog regex customtkinter
   ```

---

## 🚀 Como Executar

### ▶️ Execução Manual (Para Testes)
Para iniciar o monitoramento em tempo real:
```bash
python gui.py
```

### ⚙️ Instalação como Serviço (Recomendado)
Para que a ferramenta inicie automaticamente com o Windows:
```bash
python instalar_servico.py
```
Isso registra a ferramenta no Agendador de Tarefas do Windows, garantindo monitoramento contínuo com privilégios máximos.

### 📝 Customizar Arquivos Isca (Opcional)
- Abra o arquivo `porao.py`.
- Edite a lista `CANARY_FILES` com os arquivos/diretórios que deseja usar como isca.
- Os arquivos serão criados automaticamente na primeira execução, caso não existam.

---

## 🚀 Compilando para .exe (Instalador Final)

### Passo 1: Instalar Pré-requisitos
- **PyInstaller**: Para empacotar o código Python:
  ```bash
  pip install pyinstaller
  ```
- **Inno Setup**: Baixe e instale no site oficial: [jrsoftware.org](https://jrsoftware.org).

### Passo 2: Ajustar o Script `gui.py`
Substitua o trecho `if __name__ == "__main__":` no final do `gui.py` por:
```python
if __name__ == "__main__":
    import sys
    if "--background-service" in sys.argv:
        monitor = PoraoMonitor()
        monitor.start_monitoring()
    else:
        app = App()
        app.mainloop()
```

### Passo 3: Compilar com PyInstaller
Na pasta raiz do projeto, execute:
```bash
pyinstaller --noconsole --name="PoraoAntiRansomware" --add-data="rules;rules" gui.py
```
Isso gera a pasta `dist\PoraoAntiRansomware` com o programa compilado.

### Passo 4: Criar o Script do Instalador (`instalador.iss`)
Crie um arquivo `instalador.iss` na pasta raiz com o seguinte conteúdo:
```text
[Setup]
AppName=Porão Anti-Ransomware
AppVersion=1.0
AppPublisher=Seu Nome
DefaultDirName={autopf}\PoraoAntiRansomware
DefaultGroupName=Porão Anti-Ransomware
AllowNoIcons=yes
OutputDir=.\release
OutputBaseFilename=PoraoAntiRansomware_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin

[Languages]
Name: "portuguese"; MessagesFile: "compiler:Languages\Portuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\PoraoAntiRansomware\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Porão Anti-Ransomware"; Filename: "{app}\PoraoAntiRansomware.exe"
Name: "{autodesktop}\Porão Anti-Ransomware"; Filename: "{app}\PoraoAntiRansomware.exe"; Tasks: desktopicon

[Run]
Filename: "schtasks"; Parameters: "/Create /SC ONSTART /TN ""MonitorPoraoAntiRansomware"" /TR ""'{app}\PoraoAntiRansomware.exe' --background-service"" /RU SYSTEM /RL HIGHEST /F"; Flags: runhidden

[UninstallRun]
Filename: "schtasks"; Parameters: "/Delete /TN ""MonitorPoraoAntiRansomware"" /F"; Flags: runhidden
```

### Passo 5: Gerar o Instalador
- Clique com o botão direito em `instalador.iss` e selecione "Compile" no Inno Setup.
- O instalador `PoraoAntiRansomware_Setup.exe` será gerado na pasta `release`.

---

## ⚠️ Aviso Legal

- Esta ferramenta encerra processos críticos — **use com responsabilidade**.
- Requer privilégios de Administrador para instalação e execução.
- Desenvolvida para fins educacionais e de defesa cibernética.
- O uso indevido é de responsabilidade exclusiva do usuário.
- **Proibida qualquer forma de venda ou comercialização** deste projeto.

---

## 📚 Como Funciona: Filosofia de Defesa em Profundidade

O Porão Anti-Ransomware opera com uma abordagem híbrida, combinando:

1. **Vigilância Proativa**:
   - Monitora processos com `psutil` em alta frequência (0,05s).
   - Neutraliza ameaças no momento da execução, antes de qualquer dano.

2. **Detecção Reativa**:
   - Usa `watchdog` para monitorar eventos de arquivos em tempo real.
   - Responde instantaneamente a modificações suspeitas, como em arquivos isca.

3. **Sistema de Snapshot**:
   - Armazena o estado seguro dos arquivos para identificar alterações maliciosas.
   - Permite remediação completa, movendo arquivos afetados para quarentena.

4. **Protocolo de Resposta Unificado**:
   - Centraliza a resposta com a função `encerrar_proctree()`, garantindo neutralização e limpeza completas.

---

## 🤝 Contribuições

Contribuições são bem-vindas! Para sugerir melhorias ou relatar bugs:
1. Fork este repositório.
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`).
3. Faça commit das suas alterações (`git commit -m 'Adiciona nova funcionalidade'`).
4. Envie para o repositório remoto (`git push origin feature/nova-funcionalidade`).
5. Abra um Pull Request.

---

## 📜 Licença

Este projeto é de autoria exclusiva do desenvolvedor e não pode ser comercializado. Para mais detalhes, consulte o arquivo `LICENSE`.