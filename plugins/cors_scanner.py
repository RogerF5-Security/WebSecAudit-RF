"""
Plugin de detección de CORS Misconfiguration
"""
from typing import List
from plugins.base_plugin import BasePlugin, Finding
from utils.logger import get_logger

logger = get_logger(__name__)

class CORSScanner(BasePlugin):
    """Scanner de configuraciones CORS inseguras"""
    
    def __init__(self):
        super().__init__(
            name="CORS Misconfiguration Scanner",
            description="Detecta configuraciones CORS inseguras"
        )
        
        self.test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://evil.com.target.com",
            "https://target.com.evil.com"
        ]
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Escanea configuración CORS"""
        logger.info(f"[CORS] Iniciando escaneo en {target_url}")
        
        for origin in self.test_origins:
            headers = {"Origin": origin}
            
            response = await client.get(target_url, headers=headers)
            self.stats["requests_sent"] += 1
            
            if not response:
                continue
            
            # Verificar ACAO header
            acao = response.headers.get("Access-Control-Allow-Origin")
            acac = response.headers.get("Access-Control-Allow-Credentials")
            
            if acao:
                # CRITICAL: Refleja origin malicioso + credentials
                if acao == origin and acac == "true":
                    finding = Finding(
                        plugin_name=self.name,
                        severity="CRITICAL",
                        title="CORS Misconfiguration Crítica - Origin Reflection con Credentials",
                        description=f"El servidor refleja el origin '{origin}' y permite credentials. "
                                  f"Esto permite robo de datos mediante CORS.",
                        url=target_url,
                        parameter="Origin",
                        payload=origin,
                        request=f"GET {target_url}\nOrigin: {origin}",
                        response=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        remediation="No usar reflection de Origin. Usar whitelist estricta de origins. "
                                  "No usar Access-Control-Allow-Credentials: true con wildcards.",
                        cwe="CWE-942",
                        cvss_score=9.1
                    )
                    self.add_finding(finding)
                
                # HIGH: Wildcard con credentials
                elif acao == "*" and acac == "true":
                    finding = Finding(
                        plugin_name=self.name,
                        severity="HIGH",
                        title="CORS Misconfiguration - Wildcard con Credentials",
                        description="El servidor usa Access-Control-Allow-Origin: * con credentials habilitadas.",
                        url=target_url,
                        remediation="No combinar wildcard (*) con Access-Control-Allow-Credentials: true",
                        cwe="CWE-942",
                        cvss_score=7.5
                    )
                    self.add_finding(finding)
                
                # MEDIUM: Null origin permitido
                elif acao == "null":
                    finding = Finding(
                        plugin_name=self.name,
                        severity="MEDIUM",
                        title="CORS Misconfiguration - Null Origin Permitido",
                        description="El servidor permite origin 'null', explotable desde sandbox iframes.",
                        url=target_url,
                        remediation="No permitir origin 'null' en CORS policy",
                        cwe="CWE-942",
                        cvss_score=6.5
                    )
                    self.add_finding(finding)
        
        logger.info(f"[CORS] Escaneo completado. Hallazgos: {len(self.findings)}")
        return self.findings