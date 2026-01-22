"""
Configuración Global de la Suite de Auditoría Web
"""
import json
from pathlib import Path

# Rutas del proyecto
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
WORDLISTS_DIR = DATA_DIR / "wordlists"
REPORTS_DIR = DATA_DIR / "reports"
LOGS_DIR = DATA_DIR / "logs"

# Crear directorios si no existen
for directory in [DATA_DIR, WORDLISTS_DIR, REPORTS_DIR, LOGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Configuración de escaneo
SCAN_CONFIG = {
    "max_concurrent_requests": 50,
    "request_timeout": 15,
    "retry_attempts": 3,
    "delay_min": 0.1,  # Segundos
    "delay_max": 0.5,  # Jitter
    "follow_redirects": True,
    "verify_ssl": False,
    "max_redirects": 5
}

# Configuración de evasión WAF
EVASION_CONFIG = {
    "rotate_user_agents": True,
    "randomize_headers": True,
    "case_mutation": True,  # SQLi case mutation
    "header_fragmentation": False,  # Experimental
    "use_proxy": False,
    "proxy_rotation": False
}

# Configuración de plugins
PLUGIN_CONFIG = {
    "sqli": {
        "enabled": True,
        "time_based_delay": 5,
        "error_patterns": [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "ODBC"
        ]
    },
    "xss": {
        "enabled": True,
        "context_aware": True,
        "payloads_per_param": 10
    },
    "lfi": {
        "enabled": True,
        "depth": 5,
        "null_byte": True
    },
    "ssrf": {
        "enabled": True,
        "callback_server": None  # URL del servidor de callback
    },
    "directory_fuzzer": {
        "enabled": True,
        "wordlist": WORDLISTS_DIR / "directories.txt",
        "extensions": [".php", ".asp", ".aspx", ".jsp", ".html", ""],
        "status_codes_interesting": [200, 301, 302, 401, 403, 500]
    }
}

# Headers de seguridad
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Protege contra ataques MITM forzando HTTPS",
    "Content-Security-Policy": "Previene inyecciones de contenido (XSS, etc.)",
    "X-Frame-Options": "Previene ataques de clickjacking",
    "X-Content-Type-Options": "Previene la detección incorrecta del tipo de contenido",
    "Referrer-Policy": "Controla la información del referer",
    "Permissions-Policy": "Controla el acceso a APIs del navegador"
}

# Severidad de vulnerabilidades
SEVERITY_LEVELS = {
    "CRITICAL": {"color": "#d32f2f", "weight": 4},
    "HIGH": {"color": "#f57c00", "weight": 3},
    "MEDIUM": {"color": "#fbc02d", "weight": 2},
    "LOW": {"color": "#388e3c", "weight": 1},
    "INFO": {"color": "#1976d2", "weight": 0}
}

# Configuración de logging
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        }
    },
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": LOGS_DIR / "audit.log",
            "formatter": "json"
        },
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json"
        }
    },
    "root": {
        "level": "INFO",
        "handlers": ["file", "console"]
    }
}

def save_config(config_dict: dict, filename: str = "custom_config.json"):
    """Guarda configuración personalizada"""
    config_path = BASE_DIR / "config" / filename
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config_dict, f, indent=4)

def load_config(filename: str = "custom_config.json") -> dict:
    """Carga configuración personalizada"""
    config_path = BASE_DIR / "config" / filename
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}