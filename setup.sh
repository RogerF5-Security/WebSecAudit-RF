#!/bin/bash

# WebSecAuditSuite - Script de Instalación Automatizada
# by Roger F5

set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║   WebSecAuditSuite v2.0 - Installation Script       ║"
echo "║   by Roger F5                                        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función para imprimir con color
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[i]${NC} $1"
}

# Verificar Python
print_info "Verificando Python..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 no encontrado. Por favor instala Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
print_status "Python $PYTHON_VERSION encontrado"

# Verificar pip
print_info "Verificando pip..."
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 no encontrado. Instalando..."
    python3 -m ensurepip
fi
print_status "pip encontrado"

# Crear entorno virtual
print_info "Creando entorno virtual..."
python3 -m venv venv
print_status "Entorno virtual creado"

# Activar entorno virtual
print_info "Activando entorno virtual..."
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi
print_status "Entorno virtual activado"

# Actualizar pip
print_info "Actualizando pip..."
pip install --upgrade pip > /dev/null 2>&1
print_status "pip actualizado"

# Instalar dependencias
print_info "Instalando dependencias (esto puede tomar unos minutos)..."
pip install -r requirements.txt > /dev/null 2>&1
print_status "Dependencias instaladas"

# Crear estructura de directorios
print_info "Creando estructura de directorios..."
mkdir -p data/wordlists
mkdir -p data/reports
mkdir -p data/logs
mkdir -p config
print_status "Directorios creados"

# Crear archivos __init__.py
print_info "Creando archivos de módulos..."
touch config/__init__.py
touch core/__init__.py
touch plugins/__init__.py
touch gui/__init__.py
touch reports/__init__.py
touch utils/__init__.py
print_status "Módulos inicializados"

# Crear wordlist básica si no existe
if [ ! -f "data/wordlists/directories.txt" ]; then
    print_info "Creando wordlist de directorios básica..."
    cat > data/wordlists/directories.txt << 'EOF'
admin
login
dashboard
api
backup
.git
.env
robots.txt
phpinfo.php
wp-admin
phpmyadmin
config
database
upload
EOF
    print_status "Wordlist creada"
fi

# Verificar Nmap (opcional)
print_info "Verificando Nmap (opcional)..."
if command -v nmap &> /dev/null; then
    NMAP_VERSION=$(nmap --version | head -n1)
    print_status "$NMAP_VERSION encontrado"
else
    print_info "Nmap no encontrado (opcional). Instala con:"
    echo "   - Linux: sudo apt install nmap"
    echo "   - macOS: brew install nmap"
    echo "   - Windows: https://nmap.org/download.html"
fi

# Crear archivo de configuración inicial
if [ ! -f "config/user_settings.json" ]; then
    print_info "Creando configuración por defecto..."
    cat > config/user_settings.json << 'EOF'
{
  "scan": {
    "max_concurrent_requests": 50,
    "request_timeout": 15,
    "retry_attempts": 3,
    "delay_min": 0.1,
    "delay_max": 0.5,
    "follow_redirects": true,
    "verify_ssl": false,
    "max_redirects": 5
  },
  "evasion": {
    "rotate_user_agents": true,
    "randomize_headers": true,
    "case_mutation": true,
    "header_fragmentation": false,
    "use_proxy": false,
    "proxy_rotation": false
  },
  "proxy": {
    "enabled": false,
    "url": "",
    "type": "http"
  },
  "wordlists": {
    "directories": "data/wordlists/directories.txt",
    "sqli": "data/wordlists/sqli_payloads.txt",
    "xss": "data/wordlists/xss_payloads.txt"
  },
  "reporting": {
    "auto_open": true,
    "format": "html",
    "include_screenshots": false
  },
  "ui": {
    "theme": "dark",
    "font_size": 12,
    "console_lines": 1000
  }
}
EOF
    print_status "Configuración creada"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   ✓ Instalación Completada Exitosamente!            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
print_info "Para ejecutar WebSecAuditSuite:"
echo ""
echo "   1. Activa el entorno virtual:"
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    echo "      venv\\Scripts\\activate"
else
    echo "      source venv/bin/activate"
fi
echo ""
echo "   2. Ejecuta la aplicación:"
echo "      python main.py"
echo ""
print_info "Documentación: README.md"
print_info "Reportar bugs: https://github.com/RogerF5/WebSecAuditSuite/issues"
echo ""
print_status "¡Happy Hacking! 🛡️"
