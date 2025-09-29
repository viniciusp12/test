import customtkinter as ctk
import threading
import os
import subprocess
import time
from porao import PoraoMonitor

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- CONFIGURAÇÕES GLOBAIS DE DESIGN ---
        self.title("Porão Anti-Ransomware")
        self.geometry("1100x750")

        # Paleta de Cores (extraída da imagem de referência)
        self.COLOR_BACKGROUND = "#1A1B25"
        self.COLOR_FRAME = "#242535"
        self.COLOR_TEXT_PRIMARY = "#E0E0E0"
        self.COLOR_TEXT_SECONDARY = "#A0A0A0"
        self.COLOR_GREEN_ACCENT = "#2FA572"
        self.COLOR_BORDER = "#414257"
        self.COLOR_RED_STATUS = "#d9534f"
        self.COLOR_GREEN_STATUS = self.COLOR_GREEN_ACCENT
        self.COLOR_RISK_CRITICAL = "#d14a4a"
        self.COLOR_RISK_HIGH = "#e88f35"
        
        # Fontes
        self.FONT_FAMILY = "Segoe UI"
        self.FONT_BOLD = (self.FONT_FAMILY, 16, "bold")
        self.FONT_NORMAL = (self.FONT_FAMILY, 12)
        self.FONT_SMALL = (self.FONT_FAMILY, 10)

        # Configuração da Janela Principal
        self.configure(fg_color=self.COLOR_BACKGROUND)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # --- Variáveis de Estado ---
        self.monitor_thread = None
        self.monitor_instance = None
        self.is_monitoring = False
        self.start_time = None
        
        # --- Estrutura do Grid Principal ---
        self.grid_columnconfigure(0, weight=1) # Coluna da Esquerda
        self.grid_columnconfigure(1, weight=2) # Coluna da Direita
        self.grid_rowconfigure(1, weight=1)

        # --- RENDERIZAÇÃO DOS COMPONENTES ---
        self.create_header()
        self.create_left_column()
        self.create_right_column()

        # Inicia o loop de atualização do tempo
        self.update_active_time()

    # --- Funções de Criação de Widgets ---

    def create_header(self):
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, columnspan=2, padx=25, pady=(15, 10), sticky="ew")

        title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_frame.pack(side="left", anchor="w")
        ctk.CTkLabel(title_frame, text="Porão Anti-Ransomware", font=(self.FONT_FAMILY, 24, "bold"), text_color=self.COLOR_TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(title_frame, text="Sistema de Proteção Avançado", font=self.FONT_NORMAL, text_color=self.COLOR_TEXT_SECONDARY).pack(anchor="w")

        status_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        status_frame.pack(side="right", anchor="e")
        ctk.CTkLabel(status_frame, text="Status:", font=self.FONT_NORMAL, text_color=self.COLOR_TEXT_SECONDARY).pack(side="left")
        self.status_value = ctk.CTkLabel(status_frame, text="● INATIVO", font=(self.FONT_FAMILY, 12, "bold"), text_color=self.COLOR_RED_STATUS)
        self.status_value.pack(side="left", padx=(5, 0))

    def create_left_column(self):
        left_column_frame = ctk.CTkFrame(self, fg_color="transparent")
        left_column_frame.grid(row=1, column=0, padx=(25, 10), pady=10, sticky="nsew")
        
        # Painel de Controle
        control_panel_frame = self.create_section_frame(left_column_frame, "⚡ Painel de Controle")
        control_panel_frame.pack(fill="x", pady=(0, 20))
        
        self.start_stop_button = ctk.CTkButton(control_panel_frame, text="Iniciar Monitoramento", font=(self.FONT_FAMILY, 12, "bold"), command=self.toggle_monitoring,
                                              fg_color=self.COLOR_GREEN_ACCENT, hover_color="#288a5f", height=40, corner_radius=8)
        self.start_stop_button.pack(fill="x", padx=10, pady=(10,5))
        
        self.quarantine_button = ctk.CTkButton(control_panel_frame, text="Ver Quarentena", font=self.FONT_NORMAL, command=self.open_quarantine,
                                              fg_color="transparent", border_color=self.COLOR_BORDER, border_width=2, height=30, corner_radius=8)
        self.quarantine_button.pack(fill="x", padx=10, pady=(0, 15))

        # Estatísticas
        stats_frame = self.create_section_frame(left_column_frame, "📊 Estatísticas")
        stats_frame.pack(fill="x", expand=False)

        self.threats_label = self.create_stat_row(stats_frame, "Ameaças Bloqueadas", 1, "0")
        self.files_label = self.create_stat_row(stats_frame, "Arquivos Monitorados", 2, "0")
        self.uptime_label = self.create_stat_row(stats_frame, "Tempo Ativo", 3, "00h 00m 00s")
        self.last_check_label = self.create_stat_row(stats_frame, "Última Verificação", 4, "Nunca")

    def create_right_column(self):
        right_column_frame = ctk.CTkFrame(self, fg_color="transparent")
        right_column_frame.grid(row=1, column=1, padx=(10, 25), pady=10, sticky="nsew")
        right_column_frame.grid_rowconfigure(1, weight=1)

        # Logs
        log_frame = self.create_section_frame(right_column_frame, "🕒 Logs de Atividade")
        log_frame.pack(fill="x", pady=(0, 20), ipady=5)
        self.log_textbox = ctk.CTkTextbox(log_frame, state="disabled", wrap="word", height=200, fg_color=self.COLOR_BACKGROUND,
                                         font=self.FONT_NORMAL, text_color=self.COLOR_TEXT_SECONDARY, border_width=0)
        self.log_textbox.pack(fill="x", expand=True, padx=10, pady=(0, 10))
        self.set_log_placeholder()

        # Quarentena
        quarantine_frame = self.create_section_frame(right_column_frame, "🛡️ Quarentena")
        quarantine_frame.pack(fill="both", expand=True)
        self.quarantine_scroll_frame = ctk.CTkScrollableFrame(quarantine_frame, fg_color=self.COLOR_BACKGROUND, label_text="Arquivos isolados por atividade suspeita",
                                                             label_font=self.FONT_NORMAL, label_text_color=self.COLOR_TEXT_SECONDARY)
        self.quarantine_scroll_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    # --- Funções Auxiliares de UI ---

    def set_log_placeholder(self):
        self.log_textbox.configure(state="normal")
        self.log_textbox.delete("1.0", "end")
        self.log_textbox.insert("1.0", "Aguardando atividade do sistema...")
        self.log_textbox.configure(state="disabled", text_color=self.COLOR_TEXT_SECONDARY)
    
    def create_section_frame(self, parent, title):
        frame = ctk.CTkFrame(parent, fg_color=self.COLOR_FRAME, corner_radius=10)
        label = ctk.CTkLabel(frame, text=title, font=self.FONT_BOLD, text_color=self.COLOR_TEXT_PRIMARY)
        label.pack(anchor="w", padx=15, pady=(10, 5))
        return frame

    def create_stat_row(self, parent, text, row, initial_value):
        # Label for the stat name
        ctk.CTkLabel(parent, text=text, font=self.FONT_NORMAL, text_color=self.COLOR_TEXT_SECONDARY, anchor="w").pack(fill="x", padx=15, pady=3, side="left")
        
        # Badge frame for the value
        badge_frame = ctk.CTkFrame(parent, fg_color=self.COLOR_BACKGROUND, corner_radius=6)
        badge_frame.pack(side="right", padx=15, pady=3)
        value_label = ctk.CTkLabel(badge_frame, text=initial_value, font=(self.FONT_FAMILY, 11, "bold"), text_color=self.COLOR_TEXT_PRIMARY, anchor="e")
        value_label.pack(padx=8, pady=2)
        return value_label

    # --- Lógica da Aplicação ---

    def add_log_message(self, message):
        if self.log_textbox.get("1.0", "end-1c") == "Aguardando atividade do sistema...":
            self.log_textbox.configure(state="normal", text_color=self.COLOR_TEXT_PRIMARY)
            self.log_textbox.delete("1.0", "end")
        
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.log_textbox.configure(state="disabled")
        self.log_textbox.see("end")

    def add_quarantine_entry(self, details):
        risk_colors = {"critical": self.COLOR_RISK_CRITICAL, "high": self.COLOR_RISK_HIGH}
        risk_color = risk_colors.get(details['risk'], "gray")

        item_frame = ctk.CTkFrame(self.quarantine_scroll_frame, fg_color=self.COLOR_FRAME, corner_radius=8, border_width=1, border_color=self.COLOR_BORDER)
        item_frame.pack(fill="x", expand=True, padx=5, pady=5)
        item_frame.grid_columnconfigure(0, weight=1)

        # Linha 1: Nome do arquivo e Risco
        top_frame = ctk.CTkFrame(item_frame, fg_color="transparent")
        top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(5,0))
        ctk.CTkLabel(top_frame, text=details['file_name'], font=(self.FONT_FAMILY, 12, "bold"), text_color=self.COLOR_TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(top_frame, text=details['risk'].upper(), font=(self.FONT_FAMILY, 10, "bold"), text_color="white", fg_color=risk_color, corner_radius=8).pack(side="right")

        # Linha 2: Motivo da detecção
        ctk.CTkLabel(item_frame, text=f"Malware detectado via {details['reason']}", font=self.FONT_NORMAL, text_color=self.COLOR_TEXT_PRIMARY, wraplength=400, justify="left").grid(row=1, column=0, sticky="w", padx=10, pady=2)
        
        # Linha 3: Tamanho e Data
        ctk.CTkLabel(item_frame, text=f"{details['size_kb']} KB  |  {details['timestamp']}", font=self.FONT_SMALL, text_color=self.COLOR_TEXT_SECONDARY).grid(row=2, column=0, sticky="w", padx=10, pady=(0,5))

    def handle_backend_update(self, update_data):
        update_type = update_data.get('type')
        if update_type == 'log': self.add_log_message(update_data['message'])
        elif update_type == 'stat_update':
            stat, value = update_data['stat'], update_data['value']
            if stat == 'threats_blocked': self.threats_label.configure(text=str(value))
            elif stat == 'files_monitored': self.files_label.configure(text=f"{value:,}".replace(",", "."))
            elif stat == 'last_check': self.last_check_label.configure(text=f"{time.strftime('%H:%M:%S')}")
        elif update_type == 'quarantine_add': self.add_quarantine_entry(update_data['details'])

    def toggle_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.status_value.configure(text="● ATIVO", text_color=self.COLOR_GREEN_STATUS)
            self.start_stop_button.configure(text="Parar Monitoramento")
            self.set_log_placeholder()
            self.add_log_message("Iniciando monitoramento...")
            
            self.start_time = time.time()
            self.monitor_instance = PoraoMonitor(gui_update_callback=lambda data: self.after(0, self.handle_backend_update, data))
            self.monitor_thread = threading.Thread(target=self.monitor_instance.start_monitoring, daemon=True)
            self.monitor_thread.start()
        else:
            self.is_monitoring = False
            self.status_value.configure(text="● INATIVO", text_color=self.COLOR_RED_STATUS)
            self.start_stop_button.configure(text="Iniciar Monitoramento")
            self.add_log_message("Monitoramento interrompido pelo usuário.")
            self.start_time = None
            if self.monitor_instance: self.monitor_instance.stop_monitoring()
            self.monitor_thread = None
            self.monitor_instance = None

    def update_active_time(self):
        if self.is_monitoring and self.start_time:
            uptime = time.time() - self.start_time
            hours, rem = divmod(uptime, 3600)
            minutes, seconds = divmod(rem, 60)
            self.uptime_label.configure(text=f"{int(hours):02}h {int(minutes):02}m {int(seconds):02}s")
        self.after(1000, self.update_active_time)

    def open_quarantine(self):
        quarantine_dir = os.path.join(os.path.expanduser('~'), "Quarantine")
        if not os.path.exists(quarantine_dir): os.makedirs(quarantine_dir)
        subprocess.Popen(f'explorer "{quarantine_dir}"')

    def on_closing(self):
        if self.is_monitoring and self.monitor_instance: self.monitor_instance.stop_monitoring()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()