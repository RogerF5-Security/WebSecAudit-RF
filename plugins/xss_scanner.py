"""
Plugin de detección de Cross-Site Scripting (XSS)
Con validación de contexto para reducir falsos positivos
"""
import asyncio
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from plugins.base_plugin import BasePlugin, Finding
from config.settings import PLUGIN_CONFIG
from utils.logger import get_logger

logger = get_logger(__name__)

class XSSScanner(BasePlugin):
    """Scanner avanzado de XSS con detección de contexto"""
    
    def __init__(self):
        super().__init__(
            name="XSS Scanner",
            description="Detecta vulnerabilidades XSS (Reflected y Stored)"
        )
        self.config = PLUGIN_CONFIG["xss"]
        
        # Payloads básicos con marcador único
        self.base_payloads = [
            "<script>alert('XSS_MARKER')</script>",
            "<img src=x onerror=alert('XSS_MARKER')>",
            "<svg onload=alert('XSS_MARKER')>",
            "javascript:alert('XSS_MARKER')",
            "<iframe src=javascript:alert('XSS_MARKER')>",
            "'\"><script>alert('XSS_MARKER')</script>",
            "<body onload=alert('XSS_MARKER')>",
            "<input onfocus=alert('XSS_MARKER') autofocus>",
            "<marquee onstart=alert('XSS_MARKER')>",
            "<details open ontoggle=alert('XSS_MARKER')>"
        ]
        
        # Payloads con evasión de filtros
        self.evasion_payloads = [
            "<ScRiPt>alert('XSS_MARKER')</ScRiPt>",
            "<script>a\u006cert('XSS_MARKER')</script>",
            "<img src=x onerror=eval('al'+'ert(1)')>",
            "<svg/onload=alert('XSS_MARKER')>"
        ]
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Escanea URL en busca de XSS"""
        logger.info(f"[XSS] Iniciando escaneo en {target_url}")
        
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            logger.info(f"[XSS] No se encontraron parámetros en {target_url}")
            return []
        
        # Escanear cada parámetro
        tasks = []
        for param_name in params.keys():
            tasks.append(self._scan_parameter(target_url, param_name, client))
        
        await asyncio.gather(*tasks)
        
        logger.info(f"[XSS] Escaneo completado. Vulnerabilidades: {len(self.findings)}")
        return self.findings
    
    async def _scan_parameter(self, url: str, param_name: str, client):
        """Escanea un parámetro específico"""
        
        all_payloads = self.base_payloads + self.evasion_payloads
        payloads_to_test = all_payloads[:self.config["payloads_per_param"]]
        
        for payload in payloads_to_test:
            test_url = self._inject_payload(url, param_name, payload)
            
            response = await client.get(test_url)
            self.stats["requests_sent"] += 1
            
            if not response:
                continue
            
            # Verificar si el payload se reflejó en la respuesta
            if self._is_vulnerable(response.text, payload):
                
                # Validación de contexto para reducir falsos positivos
                context = self._detect_context(response.text, payload)
                
                severity = "HIGH" if context in ["script", "attribute"] else "MEDIUM"
                
                finding = Finding(
                    plugin_name=self.name,
                    severity=severity,
                    title=f"Cross-Site Scripting (XSS) en parámetro '{param_name}'",
                    description=f"El parámetro '{param_name}' es vulnerable a XSS. "
                              f"Contexto detectado: {context}. "
                              f"El payload se reflejó sin sanitización.",
                    url=test_url,
                    parameter=param_name,
                    payload=payload,
                    request=f"GET {test_url}",
                    response=self._extract_context_snippet(response.text, payload),
                    remediation="Implementar encoding de salida (HTML encoding). "
                              "Usar Content-Security-Policy. Validar y sanitizar entradas.",
                    cwe="CWE-79",
                    cvss_score=7.4 if severity == "HIGH" else 5.4
                )
                self.add_finding(finding)
                break  # Una vulnerabilidad por parámetro es suficiente
    
    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        """Verifica si el payload se reflejó en la respuesta"""
        # Buscar el marcador único
        if "XSS_MARKER" in response_text:
            return True
        
        # Buscar patrones específicos del payload
        patterns = [
            r"<script[^>]*>.*?alert.*?</script>",
            r"<img[^>]*onerror[^>]*>",
            r"<svg[^>]*onload[^>]*>",
            r"javascript:alert"
        ]
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_context(self, response_text: str, payload: str) -> str:
        """Detecta el contexto donde se reflejó el payload"""
        try:
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Buscar en scripts
            for script in soup.find_all('script'):
                if payload in str(script):
                    return "script"
            
            # Buscar en atributos
            for tag in soup.find_all():
                for attr_name, attr_value in tag.attrs.items():
                    if payload in str(attr_value):
                        return "attribute"
            
            # Buscar en comentarios HTML
            for comment in soup.find_all(string=lambda text: isinstance(text, str)):
                if payload in comment:
                    return "html_body"
            
        except Exception as e:
            logger.debug(f"Error detectando contexto: {e}")
        
        return "unknown"
    
    def _extract_context_snippet(self, response_text: str, payload: str) -> str:
        """Extrae un fragmento del contexto donde se reflejó el payload"""
        try:
            index = response_text.find(payload)
            if index != -1:
                start = max(0, index - 100)
                end = min(len(response_text), index + len(payload) + 100)
                snippet = response_text[start:end]
                return f"...{snippet}..."
        except Exception:
            pass
        
        return response_text[:500]
    
    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inyecta payload en un parámetro de la URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        
        return urlunparse(new_parsed)