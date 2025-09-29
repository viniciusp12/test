🛡️ Porão Anti-Ransomware
📖 Sobre o Projeto
O Porão Anti-Ransomware é uma ferramenta de segurança desenvolvida em Python, projetada para oferecer uma defesa robusta e em múltiplas camadas contra ataques de ransomware em ambientes Windows. A filosofia central do projeto é a Defesa em Profundidade Híbrida, que combina vigilância proativa para detectar ameaças antes que ajam, com detecção reativa para responder instantaneamente a atividades suspeitas no sistema de arquivos.
A ferramenta monitora processos recém-criados e atividades de modificação de arquivos em diretórios críticos do usuário, utilizando técnicas avançadas como análise de entropia, verificação de hash em bancos de dados de malware, e escaneamento com regras YARA para identificar e neutralizar ameaças em tempo real.
✨ Principais Funcionalidades

Monitoramento Proativo: Utiliza a biblioteca psutil para monitorar processos recém-criados em alta frequência, permitindo neutralizar ameaças no "segundo zero".
Detecção Reativa: Emprega a biblioteca watchdog para reagir a eventos do sistema de arquivos (criação, modificação, exclusão) em tempo real, oferecendo uma segunda camada de defesa.
Análise de Entropia: Calcula a entropia de arquivos modificados para detectar padrões de criptografia, um forte indicativo de atividade de ransomware.
Verificação de Hash (Malware DB): Gera o hash SHA256 de novos executáveis e o consulta na API do MalwareBazaar (abuse.ch) para identificar malwares conhecidos.
Scanner YARA: Escaneia novos arquivos com um conjunto de regras YARA personalizadas para identificar famílias de malware e padrões maliciosos.
Arquivos "Isca" (Canary Files): Protege arquivos "isca" em locais estratégicos. Qualquer modificação nesses arquivos aciona um alerta máximo e a neutralização imediata da ameaça.
Quarentena Segura: Isola arquivos maliciosos e os executáveis de origem em um diretório de quarentena, protegidos por senha, para evitar danos futuros.
Interface Gráfica Intuitiva: Uma interface moderna criada com CustomTkinter que exibe estatísticas em tempo real, logs de atividade e os arquivos em quarentena.

🛠️ Tecnologias Utilizadas

Linguagem: Python
Interface Gráfica: CustomTkinter
Monitoramento de Processos: psutil
Monitoramento de Arquivos: watchdog
Análise de Malware: yara-python, requests
Manipulação de Strings: regex

📦 Dependências
Para executar o projeto em um ambiente de desenvolvimento, instale as seguintes dependências:
shellpip install -r requirements.txt
Como Funciona: Documentação Técnica
A ferramenta opera sob o princípio de Defesa em Profundidade, utilizando uma arquitetura híbrida que combina vigilância proativa de processos com monitoramento reativo de arquivos em tempo real.
Filosofia Central: Defesa em Profundidade Híbrida
O princípio fundamental da ferramenta é não confiar em uma única "bala de prata". A defesa é construída em camadas, combinando duas estratégias principais:

Vigilância Proativa: Tenta ativamente encontrar o malware antes que ele cause dano.
Detecção Reativa: Reage em tempo real a ações suspeitas que já estão ocorrendo no sistema de arquivos.

Qualquer uma dessas camadas, ao detectar uma ameaça, aciona um protocolo de resposta unificado e inteligente.
Componente 1: O Vigilante Proativo de Processos
O que estamos usando?
A biblioteca psutil dentro de um loop while True de alta frequência (intervalo de 0,05s) na função novos_processos() do arquivo porao.py.
Por que disso?
Ransomwares precisam ser executados para agir. Em vez de esperar que eles modifiquem arquivos, podemos pegá-los no exato momento em que são iniciados. Um loop de alta frequência, ao contrário de um evento, nos dá controle total sobre a frequência com que verificamos por novas ameaças, tornando-nos extremamente rápidos na detecção de processos. A biblioteca psutil é a padrão e mais eficiente em Python para listar e interrogar processos do sistema.
Qual o intuito de usar isso?
O objetivo é a prevenção. Esta é a nossa primeira e mais agressiva linha de defesa, projetada para neutralizar a ameaça no "segundo zero", antes que a primeira criptografia de arquivo ocorra.
Exemplo Prático
Um usuário baixa um arquivo installer.exe malicioso e o executa. O arquivo é extraído e tenta rodar um outro processo, run.exe, de dentro da pasta C:\Users\User\AppData\Local\Temp. O loop novos_processos, rodando 20 vezes por segundo, imediatamente detecta um novo processo (run.exe) cujo caminho do executável (exe_path) começa com uma das FORBIDDEN_EXEC_PATHS. Antes mesmo que run.exe possa ler o primeiro arquivo para criptografar, encerrar_proctree() é chamado e o processo é eliminado.
Componente 2: O Sensor Reativo de Eventos de Arquivo
O que estamos usando?
A biblioteca watchdog e a classe MonitorFolder que herda de FileSystemEventHandler.
Por que disso?
O watchdog se integra diretamente com as APIs do sistema operacional (como o I/O Completion Ports no Windows) para receber notificações em tempo real sobre eventos de arquivo. Isso é muito mais eficiente do que verificar manualmente os arquivos repetidamente. Ele nos diz "algo aconteceu neste exato momento", permitindo uma reação instantânea a ações que o Vigilante Proativo possa não ter pego.
Qual o intuito de usar isso?
O objetivo é ser o gatilho de resposta rápida para qualquer interação maliciosa com o sistema de arquivos. Se o ransomware não for pego na inicialização, ele será pego assim que tocar no primeiro arquivo de forma suspeita.
Exemplo Prático
Um ransomware já em execução começa a criptografar os arquivos da pasta "Documentos". Ele encontra e modifica o arquivo dados_bancarios.xlsx, que está na lista de CANARY_FILES. No exato milissegundo em que a modificação ocorre, o watchdog notifica o MonitorFolder. A função on_modified é executada, verifica que o arquivo modificado é um arquivo isca e chama encerrar_proctree() imediatamente.
Componente 3: O Sistema de Snapshot (A "Memória")
O que estamos usando?
Funções personalizadas (criar_snapshot_arquivos, analisar_diferenca_e_agir) e um dicionário Python (SNAPSHOT_ARQUIVOS) para armazenar o estado dos arquivos.
Por que disso?
Detectar o ransomware é apenas metade da batalha. A outra metade é remediar o dano. Uma simples lista de "arquivos recentes" é imprecisa. Um snapshot nos dá uma fotografia exata do "estado seguro" do sistema (caminho e data de modificação de cada arquivo).
Qual o intuito de usar isso?
O objetivo é inteligência de resposta e remediação completa. Em vez de apenas colocar em quarentena o arquivo que disparou o alarme, garantimos que 100% dos arquivos afetados pelo ataque sejam identificados e contidos, transformando uma possível catástrofe em um incidente gerenciável.
Exemplo Prático
O antivírus detecta uma ameaça. A função encerrar_proctree chama analisar_diferenca_e_agir. Esta função varre o Desktop e encontra 15 novos arquivos .wnry que não estavam no último snapshot, além de um arquivo trabalho.docx cuja data de modificação é mais recente que a registrada no snapshot. O sistema identifica todos os 16 arquivos como parte do incidente e move cada um deles para a quarentena, limpando completamente a área de trabalho do dano visível.
Componente 4: O Protocolo de Resposta Unificado
O que estamos usando?
A função central encerrar_proctree(), que orquestra a resposta completa.
Por que disso?
Centralizar a resposta garante que, não importa como a ameaça foi detectada (seja por um processo suspeito ou por um arquivo modificado), a reação será sempre a mais forte e completa possível. Evita a duplicação de código e garante consistência.
Qual o intuito de usar isso?
O objetivo é eficácia e robustez. Garantir que cada alerta seja tratado com a máxima seriedade, executando a análise de danos, a neutralização de processos e a reconfiguração do sistema (novo snapshot) em uma sequência lógica e poderosa.
Exemplo Prático
Seja um processo rodando da pasta Temp ou um arquivo isca sendo modificado, ambos os eventos levam a uma única chamada: encerrar_proctree(). Esta função então executa sua sequência:

Chama analisar_diferenca_e_agir para conter o dano aos arquivos.
Usa taskkill para eliminar os processos.
Espera o sistema estabilizar.
Chama criar_snapshot_arquivos para preparar o sistema para o futuro.

🛠️ Instalação e Uso
🔑 Pré-requisitos

Sistema Operacional: Windows 10 ou superior
Python: 3.8+ (adicionado ao PATH do sistema)
Permissões: É necessário executar os scripts a partir de um terminal com privilégios de Administrador.

📥 Passos para Instalação

Clone o repositório (ou baixe o ZIP e extraia os arquivos):
shellgit clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
cd SEU_REPOSITORIO

Crie a pasta de regras YARA:
Dentro da pasta do projeto, crie uma subpasta chamada rules:
shellmkdir rules

Adicione as regras YARA:

Baixe os arquivos de regras (.yar) de repositórios confiáveis (como o signature-base) e coloque-os na pasta rules.
Crie um arquivo index.yar que inclua as regras que você baixou. Exemplo:
yarainclude "GEN_Ransomware.yar"
include "Crime_Generic.yar"



Instale as dependências:
Execute o seguinte comando no seu terminal:
shellpip install psutil yara-python requests watchdog regex customtkinter


🚀 Como Executar
▶️ Execução Manual (Para Testes)
Para iniciar o monitoramento em tempo real para uma sessão de teste, execute a partir de um terminal de Administrador:
shellpython gui.py
⚙️ Instalação como Serviço (Recomendado para Proteção Real)
Para que a ferramenta inicie automaticamente com o Windows e permaneça ativa, execute o instalador uma única vez a partir de um terminal de Administrador:
shellpython instalar_servico.py
Isso registrará a ferramenta no Agendador de Tarefas, garantindo que o monitoramento comece em cada inicialização, rodando de forma invisível e com privilégios máximos.
📝 Customizar Arquivos Isca (Opcional)

Abra o arquivo porao.py.
Edite a lista CANARY_FILES com os arquivos/diretórios que deseja usar como isca.
Se os arquivos não existirem, o script os criará automaticamente na primeira execução.

🚀 Compilando para .exe (Instalador Final)
Para distribuir a aplicação como um programa instalável no Windows, siga os passos abaixo.
Passo 1: Instalar os Pré-requisitos
Você precisará de duas ferramentas para compilar o projeto:

PyInstaller: Empacota o código Python e suas dependências.
shellpip install pyinstaller

Inno Setup: Cria o assistente de instalação (.exe). Faça o download no site oficial: jrsoftware.org.

Passo 2: Preparar os Scripts para Compilação
Antes de compilar, é necessário um pequeno ajuste no final do arquivo gui.py para permitir que o mesmo executável rode tanto a interface gráfica quanto o serviço de monitoramento em segundo plano.
Substitua o if __name__ == "__main__": no final do gui.py por este código:
pythonif __name__ == "__main__":
    import sys

    # Verifica se o script foi chamado com um argumento para rodar em segundo plano
    if "--background-service" in sys.argv:
        # Inicia apenas o monitor, sem interface gráfica (usado pelo serviço do Windows)
        monitor = PoraoMonitor()
        monitor.start_monitoring()
    else:
        # Inicia a aplicação com a interface gráfica normalmente
        app = App()
        app.mainloop()
Passo 3: Compilar o Código Python com PyInstaller
Abra um terminal (CMD ou PowerShell) na pasta raiz do projeto.
Garanta que a pasta rules (com suas regras YARA) está presente.
Execute o comando abaixo:
shellpyinstaller --noconsole --name="PoraoAntiRansomware" --add-data="rules;rules" gui.py

--noconsole: Impede que uma janela de console apareça.
--name: Define o nome do .exe principal.
--add-data: Inclui a pasta rules no pacote final.

Ao final, uma pasta dist\PoraoAntiRansomware será criada, contendo seu programa compilado.
Passo 4: Criar o Script do Instalador (instalador.iss)
Na pasta raiz do projeto, crie um novo arquivo de texto chamado instalador.iss.
Copie e cole o seguinte conteúdo nele. Este script diz ao Inno Setup como criar o instalador.
text; Script para o Inno Setup

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
; Copia TUDO da pasta que o PyInstaller criou para dentro do instalador.
Source: "dist\PoraoAntiRansomware\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Cria os atalhos no Menu Iniciar e na Área de Trabalho
Name: "{group}\Porão Anti-Ransomware"; Filename: "{app}\PoraoAntiRansomware.exe"
Name: "{autodesktop}\Porão Anti-Ransomware"; Filename: "{app}\PoraoAntiRansomware.exe"; Tasks: desktopicon

[Run]
; Cria a tarefa agendada para rodar o monitoramento quando o Windows iniciar.
Filename: "schtasks"; Parameters: "/Create /SC ONSTART /TN ""MonitorPoraoAntiRansomware"" /TR ""'{app}\PoraoAntiRansomware.exe' --background-service"" /RU SYSTEM /RL HIGHEST /F"; Flags: runhidden

[UninstallRun]
; Remove a tarefa agendada quando o programa for desinstalado.
Filename: "schtasks"; Parameters: "/Delete /TN ""MonitorPoraoAntiRansomware"" /F"; Flags: runhidden
Passo 5: Gerar o Instalador Final

Clique com o botão direito no arquivo instalador.iss.
Selecione a opção "Compile".
O Inno Setup irá processar o script e, se tudo estiver correto, criará uma pasta release.
Dentro da pasta release, você encontrará o PoraoAntiRansomware_Setup.exe.

Pronto! Este é o seu instalador final, pronto para ser distribuído.
⚠️ Aviso Legal

Esta ferramenta encerra processos críticos — use com responsabilidade.
A instalação e execução requerem privilégios de Administrador.
Projeto desenvolvido para fins educacionais e de defesa cibernética.
O uso indevido é de inteira responsabilidade do usuário.
🚫 É estritamente proibida qualquer forma de venda ou comercialização deste projeto. Ele é de autoria exclusiva do desenvolvedor.
