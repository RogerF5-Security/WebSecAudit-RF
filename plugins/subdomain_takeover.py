"""
Plugin de detección de Subdomain Takeover
"""
import re
from typing import List
from urllib.parse import urlparse
from plugins.base_plugin import BasePlugin, Finding
from utils.logger import get_logger

logger = get_logger(__name__)

class SubdomainTakeoverScanner(BasePlugin):
    """Scanner de vulnerabilidades de subdomain takeover"""
    
    def __init__(self):
        super().__init__(
            name="Subdomain Takeover Scanner",
            description="Detecta subdominios vulnerables a takeover"
        )
        
        # Firmas de servicios vulnerables
        self.signatures = {
            "github": {
                "cname": ["github.io", "github.com"],
                "response": ["There isn't a GitHub Pages site here"],
                "service": "GitHub Pages"
            },
            "heroku": {
                "cname": ["herokuapp.com"],
                "response": ["no such app", "There's nothing here"],
                "service": "Heroku"
            },
            "s3": {
                "cname": ["s3.amazonaws.com", "s3-website"],
                "response": ["NoSuchBucket", "The specified bucket does not exist"],
                "service": "AWS S3"
            },
            "cloudfront": {
                "cname": ["cloudfront.net"],
                "response": ["Bad Request", "ERROR: The request could not be satisfied"],
                "service": "AWS CloudFront"
            },
            "azure": {
                "cname": ["azurewebsites.net", "cloudapp.azure.com"],
                "response": ["404 Web Site not found", "Website Not Found"],
                "service": "Microsoft Azure"
            },
            "shopify": {
                "cname": ["myshopify.com"],
                "response": ["Sorry, this shop is currently unavailable"],
                "service": "Shopify"
            },
            "fastly": {
                "cname": ["fastly.net"],
                "response": ["Fastly error: unknown domain"],
                "service": "Fastly"
            }
        }
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Escanea subdomain takeover"""
        logger.info(f"[SubdomainTakeover] Iniciando escaneo en {target_url}")
        
        hostname = urlparse(target_url).hostname
        
        # Obtener respuesta del sitio
        response = await client.get(target_url)
        self.stats["requests_sent"] += 1
        
        if not response:
            return []
        
        # Verificar firmas
        for vuln_name, sig_data in self.signatures.items():
            # Verificar si algún patrón coincide en la respuesta
            for pattern in sig_data["response"]:
                if pattern.lower() in response.text.lower():
                    finding = Finding(
                        plugin_name=self.name,
                        severity="CRITICAL",
                        title=f"Subdomain Takeover Potencial - {sig_data['service']}",
                        description=f"El subdominio '{hostname}' puede ser vulnerable a takeover en {sig_data['service']}. "
                                  f"Se detectó el mensaje: '{pattern}'",
                        url=target_url,
                        request=f"GET {target_url}",
                        response=response.text[:500],
                        remediation=f"Verificar configuración de DNS para {hostname}. "
                                  f"Si el CNAME apunta a {sig_data['service']}, reclamar el recurso o eliminar el registro DNS.",
                        cwe="CWE-350",
                        cvss_score=9.3
                    )
                    self.add_finding(finding)
                    logger.info(f"[SubdomainTakeover] ✓ Posible takeover detectado: {sig_data['service']}")
        
        logger.info(f"[SubdomainTakeover] Escaneo completado. Hallazgos: {len(self.findings)}")
        return self.findings