"""
WebSecAudit-RF
Developed by Roger F5
"""
import asyncio
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
import customtkinter as ctk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import webbrowser
from pathlib import Path

# Core
from core.scanner_engine import ScannerEngine
from core.http_client import AdvancedHTTPClient

# Plugins
from plugins.crawler import WebCrawler
from plugins.sqli_scanner import SQLiScanner
from plugins.xss_scanner import XSSScanner
from plugins.lfi_scanner import LFIScanner
from plugins.ssrf_scanner import SSRFScanner
from plugins.directory_fuzzer import DirectoryFuzzer
from plugins.header_analyzer import HeaderAnalyzer
from plugins.bypass_403 import Bypass403Scanner
from plugins.nmap_scanner import NmapScanner
from plugins.cors_scanner import CORSScanner
from plugins.subdomain_takeover import SubdomainTakeoverScanner
from plugins.api_security import APISecurityScanner

# Reports
from reports.report_generator import ReportGenerator

# GUI Components
from gui.authentication_manager import AuthenticationManager
from gui.settings_manager import SettingsManager

# Utils
from utils.logger import get_logger
from config.settings import SEVERITY_LEVELS, REPORTS_DIR

logger = get_logger(__name__)

class WebSecAuditSuite(ctk.CTk):
    """Aplicación principal"""
    
    def __init__(self):
        super().__init__()
        
        # Configuración ventana
        self.title("WebSecAudit-RF")
        self.geometry("1400x900")
        
        # Variables
        self.scanner_engine = ScannerEngine()
        self.report_generator = ReportGenerator()
        self.auth_manager = AuthenticationManager()
        self.settings_manager = SettingsManager()
        self.scan_running = False
        self.stop_scan_flag = False  # Flag para detener escaneo
        
        # Registrar plugins
        self._register_plugins()
        
        # Setup GUI
        self._setup_gui()
        
        # Callbacks
        self.scanner_engine.set_progress_callback(self._update_progress)
        self.scanner_engine.set_status_callback(self._update_status)
    
    def _register_plugins(self):
        """Registra todos los plugins disponibles"""
        logger.info("Registrando plugins...")
        # CRÍTICO: El crawler debe ir primero
        self.scanner_engine.register_plugin(WebCrawler())
        self.scanner_engine.register_plugin(SQLiScanner())
        self.scanner_engine.register_plugin(XSSScanner())
        self.scanner_engine.register_plugin(LFIScanner())
        self.scanner_engine.register_plugin(SSRFScanner())
        
        # Scanners de infraestructura
        self.scanner_engine.register_plugin(NmapScanner())
        
        # Scanners de configuración
        self.scanner_engine.register_plugin(HeaderAnalyzer())
        self.scanner_engine.register_plugin(CORSScanner())
        self.scanner_engine.register_plugin(APISecurityScanner())
        
        # Bypass y evasión
        self.scanner_engine.register_plugin(Bypass403Scanner())
        
        # Fuzzing (debe ir después de bypass)
        self.scanner_engine.register_plugin(DirectoryFuzzer())
        
        # Takeover
        self.scanner_engine.register_plugin(SubdomainTakeoverScanner())
        
        logger.info(f"Total plugins registrados: {len(self.scanner_engine.plugins)}")
    
    def _setup_gui(self):
        """Configura la interfaz gráfica"""
        
        # Panel lateral izquierdo (Sidebar)
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color="#1a1a1a")
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=0, pady=0)
        self.sidebar.pack_propagate(False)
        
        # Logo/Título en sidebar
        title_label = ctk.CTkLabel(
            self.sidebar,
            text="🛡️ WebSecAudit",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#00ff88"
        )
        title_label.pack(pady=30)
        
        version_label = ctk.CTkLabel(
            self.sidebar,
            text="Beta",
            font=ctk.CTkFont(size=10),
            text_color="#888888"
        )
        version_label.pack()
        
        # Separador
        separator = ctk.CTkFrame(self.sidebar, height=2, fg_color="#333333")
        separator.pack(fill=tk.X, padx=20, pady=20)
        
        # Botones de navegación
        nav_buttons = [
            ("🎯 Scanner", self._show_scanner_view, "#00ff88"),
            ("📊 Dashboard", self._show_dashboard_view, "#4CAF50"),
            ("📄 Reports", self._show_reports_view, "#2196F3"),
            ("🔐 Auth", lambda: self.auth_manager.open_auth_window(self), "#FF9800"),
            ("⚙️ Settings", lambda: self.settings_manager.open_settings_window(self), "#9C27B0")
        ]
        
        for text, command, color in nav_buttons:
            btn = ctk.CTkButton(
                self.sidebar,
                text=text,
                command=command,
                font=ctk.CTkFont(size=14),
                height=40,
                fg_color="transparent",
                hover_color="#2a2a2a",
                border_width=2,
                border_color=color,
                text_color=color
            )
            btn.pack(pady=10, padx=20, fill=tk.X)
        
        # Footer en sidebar
        footer_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        footer_frame.pack(side=tk.BOTTOM, pady=20)
        
        ctk.CTkLabel(
            footer_frame,
            text="by Roger F5",
            font=ctk.CTkFont(size=10),
            text_color="#666666"
        ).pack()
        
        # Panel principal (derecha)
        self.main_panel = ctk.CTkFrame(self)
        self.main_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Mostrar vista de scanner por defecto
        self._show_scanner_view()
    
    def _show_scanner_view(self):
        """Vista del scanner"""
        self._clear_main_panel()
        
        # Header
        header = ctk.CTkLabel(
            self.main_panel,
            text="🎯 Web Vulnerability Scanner",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        header.pack(pady=20)
        
        # Frame de entrada
        input_frame = ctk.CTkFrame(self.main_panel)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ctk.CTkLabel(input_frame, text="Target URL:", font=ctk.CTkFont(size=14)).pack(side=tk.LEFT, padx=10)
        
        self.url_entry = ctk.CTkEntry(input_frame, width=600, height=40, font=ctk.CTkFont(size=14))
        self.url_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        self.scan_button = ctk.CTkButton(
            input_frame,
            text="🚀 Start Scan",
            command=self._start_scan_thread,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            width=150,
            fg_color="#00ff88",
            hover_color="#00cc6a",
            text_color="#000000"
        )
        self.scan_button.pack(side=tk.LEFT, padx=10)
        
        # Botón de Stop
        self.stop_button = ctk.CTkButton(
            input_frame,
            text="⛔ Stop Scan",
            command=self._stop_scan,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            width=150,
            fg_color="#ff4444",
            hover_color="#cc0000",
            text_color="#ffffff",
            state="disabled"  # Deshabilitado por defecto
        )
        self.stop_button.pack(side=tk.LEFT, padx=10)
        
        # Info de plugins
        plugins_info_frame = ctk.CTkFrame(self.main_panel)
        plugins_info_frame.pack(fill=tk.X, padx=20, pady=5)
        
        plugins_text = f"Active Plugins: {len(self.scanner_engine.plugins)} | "
        plugins_text += " | ".join([p.name.split()[0] for p in self.scanner_engine.plugins])
        
        ctk.CTkLabel(
            plugins_info_frame,
            text=plugins_text,
            font=ctk.CTkFont(size=10),
            text_color="#888888"
        ).pack(pady=5)
        
        # Barra de progreso
        progress_frame = ctk.CTkFrame(self.main_panel)
        progress_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.progress_bar = ctk.CTkProgressBar(progress_frame, height=15)
        self.progress_bar.pack(fill=tk.X, pady=5)
        self.progress_bar.set(0)
        
        # Label de estado
        self.status_label = ctk.CTkLabel(
            progress_frame,
            text="Ready to scan",
            font=ctk.CTkFont(size=12),
            text_color="#00ff88"
        )
        self.status_label.pack(pady=5)
        
        # Console/Logs
        console_frame = ctk.CTkFrame(self.main_panel)
        console_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        console_header = ctk.CTkFrame(console_frame)
        console_header.pack(fill=tk.X, padx=10, pady=5)
        
        ctk.CTkLabel(console_header, text="Console Output", font=ctk.CTkFont(size=14, weight="bold")).pack(side=tk.LEFT, padx=10)
        
        ctk.CTkButton(
            console_header,
            text="Clear",
            command=self._clear_console,
            width=80,
            height=25
        ).pack(side=tk.RIGHT, padx=10)
        
        self.console_text = scrolledtext.ScrolledText(
            console_frame,
            bg="#1e1e1e",
            fg="#00ff00",
            font=("Consolas", 10),
            height=20,
            insertbackground="#00ff00"
        )
        self.console_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _show_dashboard_view(self):
        """Vista del dashboard con gráficos"""
        self._clear_main_panel()
        
        header = ctk.CTkLabel(
            self.main_panel,
            text="📊 Security Dashboard",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        header.pack(pady=20)
        
        # Obtener resultados
        results = self.scanner_engine.get_results()
        summary = results.get("summary", {})
        
        if summary.get("total_vulnerabilities", 0) == 0:
            no_data_frame = ctk.CTkFrame(self.main_panel)
            no_data_frame.pack(expand=True)
            
            ctk.CTkLabel(
                no_data_frame,
                text="📭 No scan data available",
                font=ctk.CTkFont(size=20, weight="bold")
            ).pack(pady=20)
            
            ctk.CTkLabel(
                no_data_frame,
                text="Run a scan first to view dashboard analytics",
                font=ctk.CTkFont(size=14),
                text_color="#888888"
            ).pack()
            
            return
        
        # Stats cards
        stats_frame = ctk.CTkFrame(self.main_panel)
        stats_frame.pack(fill=tk.X, padx=20, pady=10)
        
        stats = [
            ("Total", summary.get("total_vulnerabilities", 0), "#00ff88"),
            ("Critical", summary.get("critical", 0), "#d32f2f"),
            ("High", summary.get("high", 0), "#f57c00"),
            ("Medium", summary.get("medium", 0), "#fbc02d"),
            ("Low", summary.get("low", 0), "#388e3c")
        ]
        
        for label, value, color in stats:
            card = ctk.CTkFrame(stats_frame, fg_color="#2a2a2a", corner_radius=10)
            card.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.BOTH, expand=True)
            
            ctk.CTkLabel(card, text=str(value), font=ctk.CTkFont(size=32, weight="bold"), text_color=color).pack(pady=10)
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=12), text_color="#888888").pack(pady=5)
        
        # Frame para gráficos
        graphs_frame = ctk.CTkFrame(self.main_panel)
        graphs_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Gráfico de torta
        fig = Figure(figsize=(10, 6), facecolor='#2b2b2b')
        ax = fig.add_subplot(111)
        
        data = [
            summary.get("critical", 0),
            summary.get("high", 0),
            summary.get("medium", 0),
            summary.get("low", 0)
        ]
        labels = ["Critical", "High", "Medium", "Low"]
        colors = ["#d32f2f", "#f57c00", "#fbc02d", "#388e3c"]
        
        # Filtrar valores cero
        filtered_data = [(d, l, c) for d, l, c in zip(data, labels, colors) if d > 0]
        if filtered_data:
            data, labels, colors = zip(*filtered_data)
        
        ax.pie(data, labels=labels, autopct='%1.1f%%', colors=colors, textprops={'color': 'white', 'size': 12})
        ax.set_title("Vulnerabilities by Severity", color='white', fontsize=16, pad=20)
        
        canvas = FigureCanvasTkAgg(fig, master=graphs_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def _show_reports_view(self):
        """Vista de reportes"""
        self._clear_main_panel()
        
        header = ctk.CTkLabel(
            self.main_panel,
            text="📄 Reports Manager",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        header.pack(pady=20)
        
        # Check if there are results
        results = self.scanner_engine.get_results()
        has_results = results.get("summary", {}).get("total_vulnerabilities", 0) > 0
        
        if not has_results:
            ctk.CTkLabel(
                self.main_panel,
                text="No scan results available. Run a scan first.",
                font=ctk.CTkFont(size=14),
                text_color="#888888"
            ).pack(pady=50)
            return
        
        # Generate report button
        generate_frame = ctk.CTkFrame(self.main_panel)
        generate_frame.pack(pady=30)
        
        ctk.CTkButton(
            generate_frame,
            text="📄 Generate HTML Report",
            command=self._generate_report,
            font=ctk.CTkFont(size=16, weight="bold"),
            height=50,
            width=300,
            fg_color="#2196F3",
            hover_color="#1976D2"
        ).pack(pady=10)
        
        ctk.CTkButton(
            generate_frame,
            text="📋 Export JSON",
            command=self._export_json,
            font=ctk.CTkFont(size=16, weight="bold"),
            height=50,
            width=300,
            fg_color="#4CAF50",
            hover_color="#388E3C"
        ).pack(pady=10)
        
        # List existing reports
        reports_list_frame = ctk.CTkFrame(self.main_panel)
        reports_list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(
            reports_list_frame,
            text="Recent Reports",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(anchor=tk.W, padx=10, pady=10)
        
        # Scroll frame for reports
        reports_scroll = ctk.CTkScrollableFrame(reports_list_frame, height=300)
        reports_scroll.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # List HTML reports
        report_files = sorted(REPORTS_DIR.glob("*.html"), key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not report_files:
            ctk.CTkLabel(reports_scroll, text="No reports found", text_color="#888888").pack(pady=20)
        else:
            for report_file in report_files[:10]:  # Show last 10
                report_frame = ctk.CTkFrame(reports_scroll)
                report_frame.pack(fill=tk.X, padx=5, pady=5)
                
                ctk.CTkLabel(
                    report_frame,
                    text=report_file.name,
                    font=ctk.CTkFont(size=12)
                ).pack(side=tk.LEFT, padx=10, pady=5)
                
                ctk.CTkButton(
                    report_frame,
                    text="Open",
                    command=lambda f=report_file: webbrowser.open(f.as_uri()),
                    width=80
                ).pack(side=tk.RIGHT, padx=5)
    
    def _clear_main_panel(self):
        """Limpia el panel principal"""
        for widget in self.main_panel.winfo_children():
            widget.destroy()
    
    def _clear_console(self):
        """Limpia la consola"""
        if hasattr(self, 'console_text'):
            self.console_text.delete("1.0", tk.END)
    
    def _start_scan_thread(self):
        """Inicia el escaneo en un thread separado"""
        if self.scan_running:
            messagebox.showwarning("Warning", "A scan is already running")
            return
        
        target_url = self.url_entry.get().strip()
        if not target_url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
        
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        
        self.scan_running = True
        self.stop_scan_flag = False  # Reset flag
        self.scan_button.configure(state="disabled", text="⏳ Scanning...")
        self.stop_button.configure(state="normal")  # Habilitar botón Stop
        self.console_text.delete("1.0", tk.END)
        self._log_console(f"[INFO] Starting scan of {target_url}\n")
        
        # Get proxy from settings
        proxy_url = self.settings_manager.get_proxy_url()
        
        thread = threading.Thread(target=self._run_scan, args=(target_url, proxy_url), daemon=True)
        thread.start()
    
    def _stop_scan(self):
        """Detiene el escaneo en curso"""
        if not self.scan_running:
            return
        
        self.stop_scan_flag = True
        self._log_console("\n[WARNING] ⛔ Stop requested by user...\n")
        self._update_status("Stopping scan...")
        self.stop_button.configure(state="disabled")
        
        # El escaneo se detendrá en el próximo checkpoint
        logger.info("User requested scan stop")
    
    def _run_scan(self, target_url, proxy_url):
        """Ejecuta el escaneo (en thread separado)"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Pasar flag de stop al scanner
            self.scanner_engine.stop_flag = self.stop_scan_flag
            
            loop.run_until_complete(self.scanner_engine.scan(target_url, proxy_url))
            loop.close()
            
            if self.stop_scan_flag:
                self._log_console("\n⛔ Scan stopped by user\n")
                self._log_console(f"Partial results: {len(self.scanner_engine.all_findings)} vulnerabilities found\n")
                messagebox.showinfo("Scan Stopped", "Scan stopped by user. Check partial results in Dashboard.")
            else:
                self._log_console("\n✅ Scan completed successfully!\n")
                self._log_console(f"Total vulnerabilities found: {len(self.scanner_engine.all_findings)}\n")
                messagebox.showinfo("Success", "Scan completed! Check Dashboard for results.")
            
        except Exception as e:
            logger.error(f"Scan error: {str(e)}", exc_info=True)
            self._log_console(f"\n❌ Error: {str(e)}\n")
            messagebox.showerror("Error", f"Scan failed: {str(e)}")
        
        finally:
            self.scan_running = False
            self.stop_scan_flag = False
            self.scan_button.configure(state="normal", text="🚀 Start Scan")
            self.stop_button.configure(state="disabled")
    
    def _update_progress(self, value):
        """Actualiza barra de progreso"""
        self.progress_bar.set(value / 100)
    
    def _update_status(self, message):
        """Actualiza label de estado"""
        self.status_label.configure(text=message)
        self._log_console(f"[STATUS] {message}\n")
    
    def _log_console(self, message):
        """Log en consola con formato mejorado"""
        if hasattr(self, 'console_text'):
            # Agregar timestamp
            import datetime
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            formatted_msg = f"[{timestamp}] {message}"
            
            self.console_text.insert(tk.END, formatted_msg)
            self.console_text.see(tk.END)
            
            # Auto-scroll y limitar líneas (máximo 1000)
            lines = int(self.console_text.index('end-1c').split('.')[0])
            if lines > 1000:
                self.console_text.delete('1.0', '100.0')
    
    def _generate_report(self):
        """Genera reporte HTML"""
        results = self.scanner_engine.get_results()
        
        if results.get("summary", {}).get("total_vulnerabilities", 0) == 0:
            messagebox.showwarning("Warning", "No scan results to report")
            return
        
        try:
            report_path = self.report_generator.generate_report(results)
            
            # Auto open if enabled
            if self.settings_manager.get_setting("reporting", "auto_open", True):
                webbrowser.open(report_path.as_uri())
            
            messagebox.showinfo("Success", f"Report generated:\n{report_path}")
        except Exception as e:
            logger.error(f"Report generation error: {str(e)}", exc_info=True)
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def _export_json(self):
        """Exporta resultados como JSON"""
        results = self.scanner_engine.get_results()
        
        if results.get("summary", {}).get("total_vulnerabilities", 0) == 0:
            messagebox.showwarning("Warning", "No scan results to export")
            return
        
        try:
            from datetime import datetime
            import json
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = REPORTS_DIR / f"scan_results_{timestamp}.json"
            
            # Convert findings to dict
            findings_dict = {}
            for severity, findings in results["findings_by_severity"].items():
                findings_dict[severity] = [f.to_dict() for f in findings]
            
            export_data = {
                "target": results["target"],
                "scan_stats": {
                    **results["scan_stats"],
                    "start_time": results["scan_stats"]["start_time"].isoformat(),
                    "end_time": results["scan_stats"]["end_time"].isoformat()
                },
                "summary": results["summary"],
                "findings": findings_dict
            }
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("Success", f"JSON exported:\n{json_path}")
            
        except Exception as e:
            logger.error(f"JSON export error: {str(e)}", exc_info=True)
            messagebox.showerror("Error", f"Failed to export JSON: {str(e)}")

def main():
    """Punto de entrada principal"""
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    
    logger.info("Iniciando WebSecAudit-RF")
    
    app = WebSecAuditSuite()
    app.mainloop()
    
    logger.info("Aplicación cerrada")

if __name__ == "__main__":
    main()