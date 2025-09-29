; Script para o Inno Setup

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
; Esta é a parte mágica: ele pega TUDO da pasta criada pelo PyInstaller e comprime no instalador.
Source: "dist\PoraoAntiRansomware\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Porão Anti-Ransomware"; Filename: "{app}\PoraoAntiRansomware.exe"
Name: "{autodesktop}\Porão Anti-Ransomware"; Filename: "{app}\PoraoAntiRansomware.exe"; Tasks: desktopicon

[Run]
; Cria a tarefa agendada para rodar o monitoramento quando o Windows iniciar.
Filename: "schtasks"; Parameters: "/Create /SC ONSTART /TN ""MonitorPoraoAntiRansomware"" /TR ""'{app}\PoraoAntiRansomware.exe' --background-service"" /RU SYSTEM /RL HIGHEST /F"; Flags: runhidden

[UninstallRun]
; Remove a tarefa agendada quando o programa for desinstalado.
Filename: "schtasks"; Parameters: "/Delete /TN ""MonitorPoraoAntiRansomware"" /F"; Flags: runhidden