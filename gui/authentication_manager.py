"""
Gestor de autenticación para escaneos autenticados
"""
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, scrolledtext
from typing import Dict, Optional
import json
from pathlib import Path
from config.settings import BASE_DIR

class AuthenticationManager:
    """Gestor de métodos de autenticación"""
    
    def __init__(self):
        self.auth_profiles_file = BASE_DIR / "config" / "auth_profiles.json"
        self.auth_profiles = self._load_profiles()
        self.current_auth: Optional[Dict] = None
    
    def _load_profiles(self) -> Dict:
        """Carga perfiles de autenticación guardados"""
        if self.auth_profiles_file.exists():
            try:
                with open(self.auth_profiles_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
    
    def _save_profiles(self):
        """Guarda perfiles de autenticación"""
        self.auth_profiles_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.auth_profiles_file, 'w', encoding='utf-8') as f:
            json.dump(self.auth_profiles, f, indent=2)
    
    def open_auth_window(self, parent):
        """Abre ventana de configuración de autenticación"""
        auth_window = ctk.CTkToplevel(parent)
        auth_window.title("Authentication Configuration")
        auth_window.geometry("700x600")
        
        # Título
        ctk.CTkLabel(
            auth_window,
            text="🔐 Authentication Manager",
            font=ctk.CTkFont(size=24, weight="bold")
        ).pack(pady=20)
        
        # Tabs para diferentes métodos
        tabview = ctk.CTkTabview(auth_window, width=650, height=450)
        tabview.pack(padx=20, pady=10)
        
        # Tab 1: Basic Auth
        tab_basic = tabview.add("Basic Auth")
        self._create_basic_auth_tab(tab_basic)
        
        # Tab 2: Cookies/Session
        tab_cookies = tabview.add("Cookies/Session")
        self._create_cookies_tab(tab_cookies)
        
        # Tab 3: Bearer Token
        tab_bearer = tabview.add("Bearer Token")
        self._create_bearer_tab(tab_bearer)
        
        # Tab 4: Custom Headers
        tab_headers = tabview.add("Custom Headers")
        self._create_headers_tab(tab_headers)
        
        # Botones
        button_frame = ctk.CTkFrame(auth_window)
        button_frame.pack(pady=10)
        
        ctk.CTkButton(
            button_frame,
            text="Apply & Close",
            command=lambda: self._apply_auth(auth_window, tabview),
            width=150
        ).pack(side=tk.LEFT, padx=10)
        
        ctk.CTkButton(
            button_frame,
            text="Clear Auth",
            command=self._clear_auth,
            width=150
        ).pack(side=tk.LEFT, padx=10)
    
    def _create_basic_auth_tab(self, parent):
        """Tab para Basic Authentication"""
        ctk.CTkLabel(parent, text="HTTP Basic Authentication", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        # Username
        ctk.CTkLabel(parent, text="Username:").pack(anchor=tk.W, padx=20, pady=5)
        self.basic_username = ctk.CTkEntry(parent, width=400)
        self.basic_username.pack(padx=20, pady=5)
        
        # Password
        ctk.CTkLabel(parent, text="Password:").pack(anchor=tk.W, padx=20, pady=5)
        self.basic_password = ctk.CTkEntry(parent, width=400, show="*")
        self.basic_password.pack(padx=20, pady=5)
    
    def _create_cookies_tab(self, parent):
        """Tab para Cookies/Session"""
        ctk.CTkLabel(parent, text="Session Cookies", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        ctk.CTkLabel(parent, text="Paste cookies (Format: name=value; name2=value2)").pack(anchor=tk.W, padx=20, pady=5)
        
        self.cookies_text = scrolledtext.ScrolledText(parent, height=10, width=60)
        self.cookies_text.pack(padx=20, pady=10)
        
        ctk.CTkLabel(parent, text="Example: PHPSESSID=abc123; token=xyz789").pack(pady=5)
    
    def _create_bearer_tab(self, parent):
        """Tab para Bearer Token"""
        ctk.CTkLabel(parent, text="Bearer Token / API Key", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        # Token
        ctk.CTkLabel(parent, text="Token:").pack(anchor=tk.W, padx=20, pady=5)
        self.bearer_token = ctk.CTkEntry(parent, width=500)
        self.bearer_token.pack(padx=20, pady=5)
        
        # Header name
        ctk.CTkLabel(parent, text="Header Name (default: Authorization):").pack(anchor=tk.W, padx=20, pady=5)
        self.bearer_header_name = ctk.CTkEntry(parent, width=300)
        self.bearer_header_name.insert(0, "Authorization")
        self.bearer_header_name.pack(padx=20, pady=5)
        
        # Prefix
        ctk.CTkLabel(parent, text="Prefix (e.g., 'Bearer ', leave empty if none):").pack(anchor=tk.W, padx=20, pady=5)
        self.bearer_prefix = ctk.CTkEntry(parent, width=200)
        self.bearer_prefix.insert(0, "Bearer ")
        self.bearer_prefix.pack(padx=20, pady=5)
    
    def _create_headers_tab(self, parent):
        """Tab para Custom Headers"""
        ctk.CTkLabel(parent, text="Custom Headers", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        ctk.CTkLabel(parent, text="Enter custom headers (one per line, format: Name: Value)").pack(anchor=tk.W, padx=20, pady=5)
        
        self.custom_headers_text = scrolledtext.ScrolledText(parent, height=10, width=60)
        self.custom_headers_text.pack(padx=20, pady=10)
        
        ctk.CTkLabel(parent, text="Example:\nX-API-Key: your-key-here\nX-Custom-Header: value").pack(pady=5)
    
    def _apply_auth(self, window, tabview):
        """Aplica configuración de autenticación"""
        current_tab = tabview.get()
        
        if current_tab == "Basic Auth":
            username = self.basic_username.get().strip()
            password = self.basic_password.get().strip()
            
            if username and password:
                import base64
                credentials = f"{username}:{password}"
                encoded = base64.b64encode(credentials.encode()).decode()
                
                self.current_auth = {
                    "type": "basic",
                    "headers": {
                        "Authorization": f"Basic {encoded}"
                    }
                }
                messagebox.showinfo("Success", "Basic Auth configured")
        
        elif current_tab == "Cookies/Session":
            cookies_raw = self.cookies_text.get("1.0", tk.END).strip()
            
            if cookies_raw:
                self.current_auth = {
                    "type": "cookies",
                    "headers": {
                        "Cookie": cookies_raw
                    }
                }
                messagebox.showinfo("Success", "Cookies configured")
        
        elif current_tab == "Bearer Token":
            token = self.bearer_token.get().strip()
            header_name = self.bearer_header_name.get().strip()
            prefix = self.bearer_prefix.get()
            
            if token:
                self.current_auth = {
                    "type": "bearer",
                    "headers": {
                        header_name: f"{prefix}{token}"
                    }
                }
                messagebox.showinfo("Success", "Bearer Token configured")
        
        elif current_tab == "Custom Headers":
            headers_raw = self.custom_headers_text.get("1.0", tk.END).strip()
            
            if headers_raw:
                headers = {}
                for line in headers_raw.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                
                self.current_auth = {
                    "type": "custom",
                    "headers": headers
                }
                messagebox.showinfo("Success", "Custom headers configured")
        
        window.destroy()
    
    def _clear_auth(self):
        """Limpia autenticación actual"""
        self.current_auth = None
        messagebox.showinfo("Info", "Authentication cleared")
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Retorna headers de autenticación"""
        if self.current_auth and "headers" in self.current_auth:
            return self.current_auth["headers"]
        return {}
    
    def is_authenticated(self) -> bool:
        """Verifica si hay autenticación configurada"""
        return self.current_auth is not None