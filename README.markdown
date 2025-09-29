🛡️ Porão Anti-Ransomware

Uma ferramenta de segurança proativa para Windows, desenvolvida em Python, projetada para detectar e neutralizar ataques de ransomware em tempo real. A solução utiliza uma abordagem de defesa em camadas com foco em análise de comportamento, capaz de mitigar variantes conhecidas e desconhecidas (incluindo dia zero).

🚀 Principais Funcionalidades

📂 Monitoramento em Tempo Real — Vigia continuamente diretórios críticos do usuário (Documentos, Downloads, Desktop, etc.), incluindo pastas temporárias do sistema.

🔎 Análise Heurística — Detecta criação, modificação ou exclusão massiva de arquivos em alta velocidade.

🎯 Canary Files (Arquivos Isca) — Dispara alerta imediato e de alta prioridade caso arquivos isca pré-configurados sejam tocados.

🎲 Análise de Entropia — Mede a aleatoriedade do conteúdo de um arquivo para detectar processos de criptografia.

🔬 Verificação de Hash — Compara o SHA256 de novos executáveis com o banco de dados online da MalwareBazaar.

📜 Regras YARA — Suporte a um conjunto customizável de regras YARA para identificar padrões e famílias de malware.

👨‍💻 Monitoramento de Comandos (Preventivo) — Bloqueia execuções originadas de pastas de risco (ex.: %TEMP%) e detecta comandos perigosos como vssadmin delete shadows.

⚡ Resposta Automática Inteligente — Ao detectar uma ameaça, encerra a árvore de processos maliciosos e executa um snapshot para identificar e colocar em quarentena todo o dano (arquivos novos ou modificados).

🔄 Persistência como Serviço — Script de instalação registra a ferramenta no Agendador de Tarefas do Windows para iniciar automaticamente com privilégios elevados (SYSTEM).

⚙️ Como Funciona (Visão Técnica)

A ferramenta opera com o princípio de Defesa em Profundidade Híbrida, combinando duas linhas de ação em paralelo:

🔍 Arquitetura Híbrida

Vigilante Proativo (novos_processos)

Loop de alta frequência (≈ 0.05s) que monitora processos recém-criados.

Foca em bloquear execuções a partir de caminhos proibidos e detectar comandos suspeitos.

Objetivo: prevenir antes que a primeira criptografia ocorra.

Sensor Reativo (MonitorFolder com watchdog)

Recebe eventos do sistema operacional sobre criação/modificação/exclusão de arquivos.

Reage instantaneamente a alterações em Canary Files, sinais de entropia alta ou matches YARA.

Objetivo: capturar ataques que já estão interagindo com os dados.

🛡️ Protocolo de Resposta Unificado (encerrar_proctree)

Quando qualquer motor detecta anomalia, o mesmo procedimento central é executado:

Análise de dano via snapshot (analisar_diferenca_e_agir)

Compara o estado atual com o último snapshot “limpo”.

Identifica arquivos novos/modificados e os move para quarentena.

Neutralização do processo

Encerra a árvore de processos suspeitos via taskkill.

Proteções para evitar que o antivírus se auto-encere.

Recuperação e re-armação

Aguarda estabilização (~10s) e cria um novo snapshot limpo para continuar a defesa.

🛠️ Instalação e Uso
🔑 Requisitos

SO: Windows 10 ou superior

Python: 3.8+ (adicionado ao PATH)

Permissões: Terminal executado como Administrador

📥 Passos de instalação
# Clonar o repositório
git clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
cd SEU_REPOSITORIO

# Criar pasta de regras YARA
mkdir rules


Baixe regras YARA confiáveis (ex.: signature-base) e coloque-as em rules/.

Crie um arquivo index.yar que inclua as regras desejadas:

include "GEN_Ransomware.yar"
include "Crime_Generic.yar"

📦 Instalar dependências
pip install psutil yara-python requests watchdog regex

▶️ Como Executar
Execução Manual (teste)

Abra um terminal como Administrador e rode:

python porao.py

Instalação como Serviço (recomendado)

Registra a ferramenta no Agendador de Tarefas para rodar em cada inicialização:

python instalar_servico.py


Executa o monitoramento em segundo plano com privilégios máximos (SYSTEM).

📝 Personalizações úteis

Editar Canary Files: Abra porao.py e ajuste a constante CANARY_FILES com caminhos/dados que deseja proteger. O script irá criar os arquivos automaticamente se não existirem.

Ajustar sensibilidade: Parâmetros como intervalo do loop proativo, limiar de entropia e diretórios monitorados podem ser configurados nas constantes do projeto.

Adicionar regras YARA: Atualize a pasta rules/ com novas regras e recompile/redisponibilize conforme necessário.

🧰 Compilar para .exe e criar instalador
1) Pré-requisitos

pyinstaller: pip install pyinstaller

Inno Setup (baixe de jrsoftware.org)

2) Preparar gui.py

No final de gui.py, permita rodar em modo GUI ou serviço:

if __name__ == "__main__":
    import sys
    if "--background-service" in sys.argv:
        monitor = PoraoMonitor()
        monitor.start_monitoring()
    else:
        app = App()
        app.mainloop()

3) Compilar
pyinstaller --noconsole --name="PoraoAntiRansomware" --add-data="rules;rules" gui.py

4) Script do instalador (instalador.iss)

Use o script Inno Setup para criar o instalador e criar a tarefa agendada que executa o .exe com o argumento --background-service.

📂 Estrutura sugerida do projeto
PoraoAntiRansomware/
├─ rules/                 # Regras YARA (.yar)
├─ porao.py               # Motor principal (processos, arquivos, lógica)
├─ gui.py                 # Interface com CustomTkinter
├─ instalar_servico.py    # Script para registrar no Agendador de Tarefas
├─ requirements.txt
├─ README.md

⚠️ Aviso Legal

Uso responsável: Esta ferramenta encerra processos — utilize com cautela.

Privilégios: Requer execução como Administrador.

Fins: Desenvolvido para educação e defesa cibernética.

Responsabilidade: O uso indevido é de inteira responsabilidade do usuário.

🚫 Proibida venda/comercialização — obra de autoria exclusiva do desenvolvedor.
