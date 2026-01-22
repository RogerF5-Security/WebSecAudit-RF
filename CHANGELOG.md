# Changelog

Todos los cambios notables de este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-01-22

### 🎉 Lanzamiento Inicial

Primera versión pública de WebSecAuditSuite.

### ✨ Added

#### Core Features
- Motor de escaneo asíncrono con `aiohttp`
- Sistema de plugins modular y extensible
- Interfaz gráfica moderna con CustomTkinter
- Dashboard con gráficos en tiempo real (matplotlib)
- Generación de reportes HTML5 profesionales
- Export a JSON para integración

#### Plugins de Escaneo (13 Total)
- **Web Crawler**: Descubrimiento automático de URLs con parámetros
- **SQL Injection Scanner**: Time-based y Error-based detection
- **XSS Scanner**: Context-aware con reducción de falsos positivos
- **LFI/RFI Scanner**: Local y Remote File Inclusion
- **SSRF Scanner**: Server-Side Request Forgery con bypass techniques
- **403 Bypass Scanner**: 50+ técnicas de evasión de restricciones
- **Directory Fuzzer**: Fuzzing inteligente con wordlists personalizables
- **Nmap Scanner**: Integración completa con scripts NSE
- **CORS Scanner**: Detección de misconfigurations
- **API Security Scanner**: Análisis de seguridad REST APIs
- **Security Headers Analyzer**: Análisis completo de headers HTTP
- **Subdomain Takeover Scanner**: Detección de subdominios vulnerables
- **SSL/TLS Analyzer**: Análisis de certificados y configuración

#### Evasión WAF/SOC
- User-Agent rotation automática (10+ agents reales)
- Jitter dinámico entre requests (0.1s - 0.5s)
- Randomización de headers HTTP
- Case mutation para payloads
- Soporte para proxies (HTTP/HTTPS/SOCKS5)
- Soporte para compresión Brotli

#### Autenticación
- Basic Authentication
- Bearer Token / API Keys
- Session Cookies
- Custom Headers
- Perfiles de autenticación guardables

#### Configuración
- Settings manager con persistencia JSON
- Configuración de concurrencia y timeouts
- Gestión de wordlists personalizadas
- Configuración de proxy
- Técnicas de evasión configurables

#### Reportes
- HTML5 con diseño profesional responsive
- Executive summary con gráficos de severidad
- Detalles técnicos completos (request/response)
- CVE, CWE, CVSS scores
- JSON export para automatización
- Historial de reportes en la aplicación

### 🔧 Technical Stack
- Python 3.8+
- aiohttp 3.9.1 (HTTP async)
- CustomTkinter 5.2.1 (GUI)
- BeautifulSoup4 4.12.2 (HTML parsing)
- matplotlib 3.8.2 (Gráficos)
- Jinja2 3.1.2 (Templates)
- brotli 1.1.0 (Compression)

### 📚 Documentation
- README completo con guías de instalación
- CONTRIBUTING guidelines
- Issue templates para GitHub
- Script de instalación automatizada (setup.sh)
- Ejemplos de uso

### 🐛 Known Issues
- Nmap scanner requiere Nmap instalado en el sistema
- Windows puede requerir permisos de administrador para Nmap
- Algunos WAFs pueden bloquear escaneos agresivos

### 🔒 Security
- No almacena credenciales en texto plano
- Logs sanitizados (no registra payloads sensibles completos)
- Manejo seguro de SSL/TLS con validación opcional

---

## [Unreleased]

### Planned for v2.1.0
- [ ] JWT Security Scanner
- [ ] GraphQL Introspection Scanner
- [ ] WebSocket Security Scanner
- [ ] Server-Side Template Injection (SSTI)
- [ ] XML External Entity (XXE)
- [ ] Clickjacking Scanner
- [ ] Open Redirect Scanner

### Planned for v2.2.0
- [ ] Integración con Nuclei templates
- [ ] Machine Learning para reducción de falsos positivos
- [ ] Plugin de notificaciones (Slack/Discord/Email)
- [ ] API REST para integración CI/CD
- [ ] Multi-target scanning

### Planned for v3.0.0
- [ ] Modo headless (CLI completo)
- [ ] Distributed scanning (multi-worker)
- [ ] Plugin marketplace
- [ ] Docker container
- [ ] Kubernetes deployment
- [ ] Cloud-native scanning

---

## Formato de Versiones

### [MAJOR.MINOR.PATCH]

- **MAJOR**: Cambios incompatibles con versiones anteriores
- **MINOR**: Nuevas funcionalidades compatibles con versiones anteriores
- **PATCH**: Correcciones de bugs compatibles

### Tipos de Cambios

- **Added**: Nuevas funcionalidades
- **Changed**: Cambios en funcionalidades existentes
- **Deprecated**: Funcionalidades que serán removidas
- **Removed**: Funcionalidades removidas
- **Fixed**: Corrección de bugs
- **Security**: Correcciones de seguridad

---

[2.0.0]: https://github.com/RogerF5/WebSecAuditSuite/releases/tag/v2.0.0
[Unreleased]: https://github.com/RogerF5/WebSecAuditSuite/compare/v2.0.0...HEAD
