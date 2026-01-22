"""
Gestor de configuración persistente de la aplicación
"""
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, filedialog
import json
from pathlib import Path
from config.settings import BASE_DIR, SCAN_CONFIG, EVASION_CONFIG

class SettingsManager:
    """Gestor de configuración de la aplicación"""
    
    def __init__(self):
        self.settings_file = BASE_DIR / "config" / "user_settings.json"
        self.settings = self._load_settings()
    
    def _load_settings(self) -> dict:
        """Carga configuración guardada"""
        if self.settings_file.exists():
            try:
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return self._default_settings()
        return self._default_settings()
    
    def _default_settings(self) -> dict:
        """Retorna configuración por defecto"""
        return {
            "scan": SCAN_CONFIG.copy(),
            "evasion": EVASION_CONFIG.copy(),
            "proxy": {
                "enabled": False,
                "url": "",
                "type": "http"
            },
            "wordlists": {
                "directories": str(BASE_DIR / "data" / "wordlists" / "directories.txt"),
                "sqli": str(BASE_DIR / "data" / "wordlists" / "sqli_payloads.txt"),
                "xss": str(BASE_DIR / "data" / "wordlists" / "xss_payloads.txt")
            },
            "reporting": {
                "auto_open": True,
                "format": "html",
                "include_screenshots": False
            },
            "ui": {
                "theme": "dark",
                "font_size": 12,
                "console_lines": 1000
            }
        }
    
    def _save_settings(self):
        """Guarda configuración"""
        self.settings_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.settings_file, 'w', encoding='utf-8') as f:
            json.dump(self.settings, f, indent=2)
    
    def open_settings_window(self, parent):
        """Abre ventana de configuración"""
        settings_window = ctk.CTkToplevel(parent)
        settings_window.title("Settings")
        settings_window.geometry("800x700")
        
        # Título
        ctk.CTkLabel(
            settings_window,
            text="⚙️ Application Settings",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Tabs
        tabview = ctk.CTkTabview(settings_window, width=750, height=550)
        tabview.pack(padx=20, pady=10)
        
        # Tab 1: Scan Settings
        tab_scan = tabview.add("Scan")
        self._create_scan_tab(tab_scan)
        
        # Tab 2: Evasion
        tab_evasion = tabview.add("Evasion")
        self._create_evasion_tab(tab_evasion)
        
        # Tab 3: Proxy
        tab_proxy = tabview.add("Proxy")
        self._create_proxy_tab(tab_proxy)
        
        # Tab 4: Wordlists
        tab_wordlists = tabview.add("Wordlists")
        self._create_wordlists_tab(tab_wordlists)
        
        # Tab 5: Reporting
        tab_reporting = tabview.add("Reporting")
        self._create_reporting_tab(tab_reporting)
        
        # Botones
        button_frame = ctk.CTkFrame(settings_window)
        button_frame.pack(pady=10)
        
        ctk.CTkButton(
            button_frame,
            text="Save & Apply",
            command=lambda: self._save_and_apply(settings_window),
            width=150
        ).pack(side=tk.LEFT, padx=10)
        
        ctk.CTkButton(
            button_frame,
            text="Reset to Defaults",
            command=self._reset_defaults,
            width=150
        ).pack(side=tk.LEFT, padx=10)
        
        ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=settings_window.destroy,
            width=150
        ).pack(side=tk.LEFT, padx=10)
    
    def _create_scan_tab(self, parent):
        """Tab de configuración de escaneo"""
        frame = ctk.CTkScrollableFrame(parent, width=700, height=450)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Max concurrent requests
        ctk.CTkLabel(frame, text="Max Concurrent Requests:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor=tk.W, pady=5)
        self.max_concurrent = ctk.CTkEntry(frame, width=100)
        self.max_concurrent.insert(0, str(self.settings["scan"]["max_concurrent_requests"]))
        self.max_concurrent.pack(anchor=tk.W, padx=20)
        
        # Request timeout
        ctk.CTkLabel(frame, text="Request Timeout (seconds):", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor=tk.W, pady=5)
        self.request_timeout = ctk.CTkEntry(frame, width=100)
        self.request_timeout.insert(0, str(self.settings["scan"]["request_timeout"]))
        self.request_timeout.pack(anchor=tk.W, padx=20)
        
        # Retry attempts
        ctk.CTkLabel(frame, text="Retry Attempts:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor=tk.W, pady=5)
        self.retry_attempts = ctk.CTkEntry(frame, width=100)
        self.retry_attempts.insert(0, str(self.settings["scan"]["retry_attempts"]))
        self.retry_attempts.pack(anchor=tk.W, padx=20)
        
        # Delay
        ctk.CTkLabel(frame, text="Delay Between Requests (seconds):", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor=tk.W, pady=5)
        delay_frame = ctk.CTkFrame(frame)
        delay_frame.pack(anchor=tk.W, padx=20, pady=5)
        
        ctk.CTkLabel(delay_frame, text="Min:").pack(side=tk.LEFT, padx=5)
        self.delay_min = ctk.CTkEntry(delay_frame, width=60)
        self.delay_min.insert(0, str(self.settings["scan"]["delay_min"]))
        self.delay_min.pack(side=tk.LEFT, padx=5)
        
        ctk.CTkLabel(delay_frame, text="Max:").pack(side=tk.LEFT, padx=5)
        self.delay_max = ctk.CTkEntry(delay_frame, width=60)
        self.delay_max.insert(0, str(self.settings["scan"]["delay_max"]))
        self.delay_max.pack(side=tk.LEFT, padx=5)
        
        # Follow redirects
        self.follow_redirects = ctk.CTkCheckBox(frame, text="Follow Redirects")
        self.follow_redirects.pack(anchor=tk.W, padx=20, pady=5)
        if self.settings["scan"]["follow_redirects"]:
            self.follow_redirects.select()
        
        # Verify SSL
        self.verify_ssl = ctk.CTkCheckBox(frame, text="Verify SSL Certificates")
        self.verify_ssl.pack(anchor=tk.W, padx=20, pady=5)
        if self.settings["scan"]["verify_ssl"]:
            self.verify_ssl.select()
    
    def _create_evasion_tab(self, parent):
        """Tab de configuración de evasión"""
        frame = ctk.CTkScrollableFrame(parent, width=700, height=450)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ctk.CTkLabel(frame, text="WAF/IDS Evasion Techniques", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        
        # Rotate user agents
        self.rotate_ua = ctk.CTkCheckBox(frame, text="Rotate User-Agents")
        self.rotate_ua.pack(anchor=tk.W, padx=20, pady=5)
        if self.settings["evasion"]["rotate_user_agents"]:
            self.rotate_ua.select()
        
        # Randomize headers
        self.randomize_headers = ctk.CTkCheckBox(frame, text="Randomize Headers")
        self.randomize_headers.pack(anchor=tk.W, padx=20, pady=5)
        if self.settings["evasion"]["randomize_headers"]:
            self.randomize_headers.select()
        
        # Case mutation
        self.case_mutation = ctk.CTkCheckBox(frame, text="Case Mutation (SQLi)")
        self.case_mutation.pack(anchor=tk.W, padx=20, pady=5)
        if self.settings["evasion"]["case_mutation"]:
            self.case_mutation.select()
        
        # Header fragmentation
        self.header_frag = ctk.CTkCheckBox(frame, text="Header Fragmentation (Experimental)")
        self.header_frag.pack(anchor=tk.W, padx=20, pady=5)
        if self.settings["evasion"]["header_fragmentation"]:
            self.header_frag.select()
    
    def _create_proxy_tab(self, parent):
        """Tab de configuración de proxy"""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Enable proxy
        self.proxy_enabled = ctk.CTkCheckBox(frame, text="Enable Proxy")
        self.proxy_enabled.pack(anchor=tk.W, padx=20, pady=10)
        if self.settings["proxy"]["enabled"]:
            self.proxy_enabled.select()
        
        # Proxy URL
        ctk.CTkLabel(frame, text="Proxy URL (e.g., http://127.0.0.1:8080):").pack(anchor=tk.W, padx=20, pady=5)
        self.proxy_url = ctk.CTkEntry(frame, width=400)
        self.proxy_url.insert(0, self.settings["proxy"]["url"])
        self.proxy_url.pack(padx=20, pady=5)
        
        # Proxy type
        ctk.CTkLabel(frame, text="Proxy Type:").pack(anchor=tk.W, padx=20, pady=5)
        self.proxy_type = ctk.CTkOptionMenu(frame, values=["http", "https", "socks5"])
        self.proxy_type.set(self.settings["proxy"]["type"])
        self.proxy_type.pack(anchor=tk.W, padx=20, pady=5)
    
    def _create_wordlists_tab(self, parent):
        """Tab de configuración de wordlists"""
        frame = ctk.CTkScrollableFrame(parent, width=700, height=450)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Directories wordlist
        ctk.CTkLabel(frame, text="Directories Wordlist:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor=tk.W, pady=5)
        self.wordlist_dir = ctk.CTkEntry(frame, width=500)
        self.wordlist_dir.insert(0, self.settings["wordlists"]["directories"])
        self.wordlist_dir.pack(anchor=tk.W, padx=20, pady=5)
        ctk.CTkButton(frame, text="Browse", command=lambda: self._browse_file(self.wordlist_dir)).pack(anchor=tk.W, padx=20, pady=5)
        
        # SQLi wordlist
        ctk.CTkLabel(frame, text="SQLi Wordlist:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor=tk.W, pady=5)
        self.wordlist_sqli = ctk.CTkEntry(frame, width=500)
        self.wordlist_sqli.insert(0, self.settings["wordlists"]["sqli"])
        self.wordlist_sqli.pack(anchor=tk.W, padx=20, pady=5)
        ctk.CTkButton(frame, text="Browse", command=lambda: self._browse_file(self.wordlist_sqli)).pack(anchor=tk.W, padx=20, pady=5)
        
        # XSS wordlist
        ctk.CTkLabel(frame, text="XSS Wordlist:", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor=tk.W, pady=5)
        self.wordlist_xss = ctk.CTkEntry(frame, width=500)
        self.wordlist_xss.insert(0, self.settings["wordlists"]["xss"])
        self.wordlist_xss.pack(anchor=tk.W, padx=20, pady=5)
        ctk.CTkButton(frame, text="Browse", command=lambda: self._browse_file(self.wordlist_xss)).pack(anchor=tk.W, padx=20, pady=5)
    
    def _create_reporting_tab(self, parent):
        """Tab de configuración de reportes"""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Auto open report
        self.auto_open_report = ctk.CTkCheckBox(frame, text="Auto-open Report After Generation")
        self.auto_open_report.pack(anchor=tk.W, padx=20, pady=10)
        if self.settings["reporting"]["auto_open"]:
            self.auto_open_report.select()
        
        # Format
        ctk.CTkLabel(frame, text="Report Format:").pack(anchor=tk.W, padx=20, pady=5)
        self.report_format = ctk.CTkOptionMenu(frame, values=["html", "json", "pdf"])
        self.report_format.set(self.settings["reporting"]["format"])
        self.report_format.pack(anchor=tk.W, padx=20, pady=5)
    
    def _browse_file(self, entry_widget):
        """Abre diálogo para seleccionar archivo"""
        filename = filedialog.askopenfilename()
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)
    
    def _save_and_apply(self, window):
        """Guarda y aplica configuración"""
        try:
            # Scan settings
            self.settings["scan"]["max_concurrent_requests"] = int(self.max_concurrent.get())
            self.settings["scan"]["request_timeout"] = int(self.request_timeout.get())
            self.settings["scan"]["retry_attempts"] = int(self.retry_attempts.get())
            self.settings["scan"]["delay_min"] = float(self.delay_min.get())
            self.settings["scan"]["delay_max"] = float(self.delay_max.get())
            self.settings["scan"]["follow_redirects"] = self.follow_redirects.get() == 1
            self.settings["scan"]["verify_ssl"] = self.verify_ssl.get() == 1
            
            # Evasion settings
            self.settings["evasion"]["rotate_user_agents"] = self.rotate_ua.get() == 1
            self.settings["evasion"]["randomize_headers"] = self.randomize_headers.get() == 1
            self.settings["evasion"]["case_mutation"] = self.case_mutation.get() == 1
            self.settings["evasion"]["header_fragmentation"] = self.header_frag.get() == 1
            
            # Proxy settings
            self.settings["proxy"]["enabled"] = self.proxy_enabled.get() == 1
            self.settings["proxy"]["url"] = self.proxy_url.get().strip()
            self.settings["proxy"]["type"] = self.proxy_type.get()
            
            # Wordlists
            self.settings["wordlists"]["directories"] = self.wordlist_dir.get().strip()
            self.settings["wordlists"]["sqli"] = self.wordlist_sqli.get().strip()
            self.settings["wordlists"]["xss"] = self.wordlist_xss.get().strip()
            
            # Reporting
            self.settings["reporting"]["auto_open"] = self.auto_open_report.get() == 1
            self.settings["reporting"]["format"] = self.report_format.get()
            
            self._save_settings()
            messagebox.showinfo("Success", "Settings saved successfully!")
            window.destroy()
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid value: {str(e)}")
    
    def _reset_defaults(self):
        """Restaura configuración por defecto"""
        if messagebox.askyesno("Confirm", "Reset all settings to defaults?"):
            self.settings = self._default_settings()
            self._save_settings()
            messagebox.showinfo("Success", "Settings reset to defaults. Please reopen settings window.")
    
    def get_setting(self, category: str, key: str, default=None):
        """Obtiene un valor de configuración"""
        return self.settings.get(category, {}).get(key, default)
    
    def get_proxy_url(self) -> str:
        """Retorna URL del proxy si está habilitado"""
        if self.settings["proxy"]["enabled"]:
            return self.settings["proxy"]["url"]
        return ""