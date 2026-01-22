"""
Plugin de detección de Server-Side Request Forgery (SSRF)
"""
import asyncio
import time
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from plugins.base_plugin import BasePlugin, Finding
from config.settings import PLUGIN_CONFIG
from utils.logger import get_logger

logger = get_logger(__name__)

class SSRFScanner(BasePlugin):
    """Scanner de vulnerabilidades SSRF"""
    
    def __init__(self):
        super().__init__(
            name="SSRF Scanner",
            description="Detecta vulnerabilidades Server-Side Request Forgery"
        )
        self.config = PLUGIN_CONFIG["ssrf"]
        
        # Payloads SSRF internos
        self.internal_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
            "http://169.254.169.254/metadata/instance",  # Azure metadata
            "http://192.168.0.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
        ]
        
        # Payloads con bypass
        self.bypass_payloads = [
            "http://127.1",
            "http://0177.0.0.1",  # Octal
            "http://2130706433",  # Decimal
            "http://localhost#@evil.com",
            "http://evil.com#@localhost",
            "http://127.0.0.1.nip.io",
            "http://localtest.me",
        ]
        
        # Patrones de éxito (metadata leaks)
        self.success_indicators = [
            "ami-id",
            "instance-id",
            "iam/security-credentials",
            "computeMetadata",
            "instanceMetadata",
            '"privateIpAddress"',
            '"region"',
        ]
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Escanea URL en busca de SSRF"""
        logger.info(f"[SSRF] Iniciando escaneo en {target_url}")
        
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            logger.info(f"[SSRF] No se encontraron parámetros en {target_url}")
            return []
        
        # Escanear cada parámetro que parezca una URL
        tasks = []
        for param_name, param_value in params.items():
            # Verificar si el parámetro parece una URL
            if self._looks_like_url_param(param_name, param_value):
                tasks.append(self._scan_parameter(target_url, param_name, client))
        
        if tasks:
            await asyncio.gather(*tasks)
        else:
            logger.info("[SSRF] No se encontraron parámetros tipo URL")
        
        logger.info(f"[SSRF] Escaneo completado. Vulnerabilidades: {len(self.findings)}")
        return self.findings
    
    def _looks_like_url_param(self, param_name: str, param_value: List[str]) -> bool:
        """Verifica si un parámetro parece contener una URL"""
        url_indicators = ["url", "uri", "link", "redirect", "goto", "callback", "webhook", "fetch"]
        
        # Verificar nombre del parámetro
        if any(indicator in param_name.lower() for indicator in url_indicators):
            return True
        
        # Verificar valor del parámetro
        if param_value and len(param_value) > 0:
            value = param_value[0]
            if value.startswith(("http://", "https://", "//")):
                return True
        
        return False
    
    async def _scan_parameter(self, url: str, param_name: str, client):
        """Escanea un parámetro específico"""
        
        all_payloads = self.internal_payloads + self.bypass_payloads
        
        # Primero obtener respuesta normal
        baseline_response = await client.get(url)
        if not baseline_response:
            return
        
        baseline_length = len(baseline_response.text)
        baseline_time = baseline_response.elapsed
        
        for payload in all_payloads:
            test_url = self._inject_payload(url, param_name, payload)
            
            start_time = time.time()
            response = await client.get(test_url)
            elapsed_time = time.time() - start_time
            
            self.stats["requests_sent"] += 1
            
            if not response:
                continue
            
            # Verificar indicadores de éxito
            vuln_detected = False
            detected_indicator = None
            
            # 1. Buscar patrones de metadata
            for indicator in self.success_indicators:
                if indicator in response.text:
                    vuln_detected = True
                    detected_indicator = indicator
                    break
            
            # 2. Diferencias significativas en longitud de respuesta
            if abs(len(response.text) - baseline_length) > 500:
                vuln_detected = True
            
            # 3. Tiempo de respuesta anormal (timeout interno)
            if elapsed_time > 10 and elapsed_time > baseline_time + 5:
                vuln_detected = True
                detected_indicator = "Internal timeout detected"
            
            if vuln_detected:
                severity = "CRITICAL" if any(kw in payload for kw in ["169.254.169.254", "metadata"]) else "HIGH"
                
                finding = Finding(
                    plugin_name=self.name,
                    severity=severity,
                    title=f"Server-Side Request Forgery en parámetro '{param_name}'",
                    description=f"El parámetro '{param_name}' es vulnerable a SSRF. "
                              f"El servidor realiza peticiones a URLs controladas por el atacante. "
                              f"Indicador detectado: {detected_indicator or 'Cambio en respuesta'}",
                    url=test_url,
                    parameter=param_name,
                    payload=payload,
                    request=f"GET {test_url}",
                    response=response.text[:500],
                    remediation="Validar y sanitizar todas las URLs de entrada. Usar whitelist de dominios permitidos. "
                              "Implementar firewall de egress. Deshabilitar redirects automáticos. "
                              "Validar esquemas de URL (permitir solo http/https).",
                    cwe="CWE-918",
                    cvss_score=9.1 if severity == "CRITICAL" else 8.2
                )
                self.add_finding(finding)
                return  # Una vulnerabilidad por parámetro
    
    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inyecta payload en un parámetro de la URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        
        return urlunparse(new_parsed)