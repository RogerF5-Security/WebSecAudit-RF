"""
Plugin de análisis de headers de seguridad HTTP
"""
from typing import List, Dict
from plugins.base_plugin import BasePlugin, Finding
from config.settings import SECURITY_HEADERS
from utils.logger import get_logger

logger = get_logger(__name__)

class HeaderAnalyzer(BasePlugin):
    """Analizador de headers de seguridad HTTP"""
    
    def __init__(self):
        super().__init__(
            name="Security Headers Analyzer",
            description="Analiza headers de seguridad HTTP y detecta configuraciones inseguras"
        )
        
        # Headers que NO deben estar presentes
        self.bad_headers = {
            "Server": "Revela información del servidor",
            "X-Powered-By": "Revela tecnología del servidor",
            "X-AspNet-Version": "Revela versión de ASP.NET",
            "X-AspNetMvc-Version": "Revela versión de ASP.NET MVC"
        }
        
        # Configuraciones inseguras de CSP
        self.insecure_csp_directives = [
            "unsafe-inline",
            "unsafe-eval",
            "*"  # Wildcard
        ]
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Analiza headers de seguridad"""
        logger.info(f"[Headers] Analizando headers de {target_url}")
        
        # Obtener headers
        response = await client.get(target_url)
        self.stats["requests_sent"] += 1
        
        if not response:
            logger.warning(f"[Headers] No se pudo obtener respuesta de {target_url}")
            return []
        
        headers = response.headers
        
        # 1. Verificar headers de seguridad faltantes
        self._check_missing_security_headers(headers, target_url)
        
        # 2. Verificar headers que revelan información
        self._check_information_disclosure(headers, target_url)
        
        # 3. Análisis específico de CSP
        self._analyze_csp(headers, target_url)
        
        # 4. Análisis de cookies
        self._analyze_cookies(headers, target_url)
        
        logger.info(f"[Headers] Análisis completado. Hallazgos: {len(self.findings)}")
        return self.findings
    
    def _check_missing_security_headers(self, headers: Dict, url: str):
        """Verifica headers de seguridad faltantes"""
        
        for header_name, description in SECURITY_HEADERS.items():
            if header_name not in headers:
                severity = self._get_severity_for_missing_header(header_name)
                
                finding = Finding(
                    plugin_name=self.name,
                    severity=severity,
                    title=f"Header de seguridad faltante: {header_name}",
                    description=f"El header '{header_name}' no está presente. {description}",
                    url=url,
                    parameter=None,
                    payload=None,
                    request=f"GET {url}",
                    response=f"Header '{header_name}' ausente",
                    remediation=self._get_remediation_for_header(header_name),
                    cwe="CWE-16",
                    cvss_score=self._get_cvss_for_header(header_name)
                )
                self.add_finding(finding)
    
    def _check_information_disclosure(self, headers: Dict, url: str):
        """Verifica headers que revelan información"""
        
        for header_name, description in self.bad_headers.items():
            if header_name in headers:
                finding = Finding(
                    plugin_name=self.name,
                    severity="LOW",
                    title=f"Divulgación de información: {header_name}",
                    description=f"El header '{header_name}' revela información del servidor: "
                              f"{headers[header_name]}. {description}",
                    url=url,
                    parameter=None,
                    payload=None,
                    request=f"GET {url}",
                    response=f"{header_name}: {headers[header_name]}",
                    remediation=f"Eliminar o ofuscar el header '{header_name}' en la configuración del servidor.",
                    cwe="CWE-200",
                    cvss_score=3.7
                )
                self.add_finding(finding)
    
    def _analyze_csp(self, headers: Dict, url: str):
        """Analiza Content-Security-Policy"""
        
        if "Content-Security-Policy" not in headers:
            return  # Ya reportado en headers faltantes
        
        csp_value = headers["Content-Security-Policy"]
        
        # Buscar directivas inseguras
        insecure_directives_found = []
        for directive in self.insecure_csp_directives:
            if directive in csp_value:
                insecure_directives_found.append(directive)
        
        if insecure_directives_found:
            finding = Finding(
                plugin_name=self.name,
                severity="MEDIUM",
                title="Content-Security-Policy con directivas inseguras",
                description=f"La política CSP contiene directivas inseguras: {', '.join(insecure_directives_found)}. "
                          f"Esto reduce la efectividad de la protección contra XSS.",
                url=url,
                parameter=None,
                payload=None,
                request=f"GET {url}",
                response=f"CSP: {csp_value}",
                remediation="Evitar 'unsafe-inline' y 'unsafe-eval'. Usar nonces o hashes para scripts inline. "
                          "Especificar dominios exactos en lugar de wildcards.",
                cwe="CWE-1021",
                cvss_score=5.3
            )
            self.add_finding(finding)
    
    def _analyze_cookies(self, headers: Dict, url: str):
        """Analiza flags de seguridad en cookies"""
        
        set_cookie_headers = []
        
        # Buscar todos los headers Set-Cookie
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                set_cookie_headers.append(value)
        
        for cookie_value in set_cookie_headers:
            cookie_name = cookie_value.split("=")[0] if "=" in cookie_value else "unknown"
            
            issues = []
            
            if "Secure" not in cookie_value:
                issues.append("sin flag Secure")
            
            if "HttpOnly" not in cookie_value:
                issues.append("sin flag HttpOnly")
            
            if "SameSite" not in cookie_value:
                issues.append("sin flag SameSite")
            
            if issues:
                finding = Finding(
                    plugin_name=self.name,
                    severity="MEDIUM",
                    title=f"Cookie insegura: {cookie_name}",
                    description=f"La cookie '{cookie_name}' tiene las siguientes deficiencias: {', '.join(issues)}.",
                    url=url,
                    parameter=None,
                    payload=None,
                    request=f"GET {url}",
                    response=f"Set-Cookie: {cookie_value[:100]}",
                    remediation="Establecer flags Secure, HttpOnly y SameSite=Strict/Lax en todas las cookies. "
                              "Secure asegura transmisión solo por HTTPS. "
                              "HttpOnly previene acceso desde JavaScript. "
                              "SameSite previene CSRF.",
                    cwe="CWE-614",
                    cvss_score=5.3
                )
                self.add_finding(finding)
    
    def _get_severity_for_missing_header(self, header_name: str) -> str:
        """Determina severidad de un header faltante"""
        critical_headers = ["Strict-Transport-Security"]
        high_headers = ["Content-Security-Policy", "X-Frame-Options"]
        
        if header_name in critical_headers:
            return "HIGH"
        elif header_name in high_headers:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_remediation_for_header(self, header_name: str) -> str:
        """Retorna recomendación específica para cada header"""
        remediations = {
            "Strict-Transport-Security": "Agregar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "Content-Security-Policy": "Implementar CSP restrictiva. Ejemplo: default-src 'self'; script-src 'self' 'nonce-random'",
            "X-Frame-Options": "Agregar: X-Frame-Options: DENY o SAMEORIGIN",
            "X-Content-Type-Options": "Agregar: X-Content-Type-Options: nosniff",
            "Referrer-Policy": "Agregar: Referrer-Policy: strict-origin-when-cross-origin",
            "Permissions-Policy": "Agregar: Permissions-Policy: geolocation=(), microphone=(), camera=()"
        }
        
        return remediations.get(header_name, f"Implementar header {header_name} según best practices.")
    
    def _get_cvss_for_header(self, header_name: str) -> float:
        """Retorna score CVSS aproximado"""
        scores = {
            "Strict-Transport-Security": 7.4,
            "Content-Security-Policy": 6.5,
            "X-Frame-Options": 5.3,
            "X-Content-Type-Options": 4.3,
            "Referrer-Policy": 3.7,
            "Permissions-Policy": 3.1
        }
        
        return scores.get(header_name, 3.0)