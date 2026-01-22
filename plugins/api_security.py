"""
Plugin de análisis de seguridad de APIs REST
"""
import json
from typing import List
from urllib.parse import urljoin
from plugins.base_plugin import BasePlugin, Finding
from utils.logger import get_logger

logger = get_logger(__name__)

class APISecurityScanner(BasePlugin):
    """Scanner de seguridad para APIs REST"""
    
    def __init__(self):
        super().__init__(
            name="API Security Scanner",
            description="Analiza seguridad de endpoints de API REST"
        )
        
        self.api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/graphql", "/swagger", "/api-docs",
            "/v1", "/v2", "/v3"
        ]
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Escanea seguridad de APIs"""
        logger.info(f"[API] Iniciando escaneo de API en {target_url}")
        
        base_url = target_url.rstrip('/')
        
        # 1. Descubrir endpoints de API
        api_endpoints = await self._discover_api_endpoints(base_url, client)
        
        if not api_endpoints:
            logger.info("[API] No se encontraron endpoints de API")
            return []
        
        logger.info(f"[API] Encontrados {len(api_endpoints)} endpoints de API")
        
        # 2. Testear cada endpoint
        for endpoint in api_endpoints:
            await self._test_api_endpoint(endpoint, client)
        
        logger.info(f"[API] Escaneo completado. Hallazgos: {len(self.findings)}")
        return self.findings
    
    async def _discover_api_endpoints(self, base_url: str, client) -> List[str]:
        """Descubre endpoints de API"""
        endpoints = []
        
        for path in self.api_paths:
            url = base_url + path
            response = await client.get(url)
            self.stats["requests_sent"] += 1
            
            if response and response.status in [200, 401, 403]:
                endpoints.append(url)
                logger.info(f"[API] ✓ Endpoint encontrado: {url}")
        
        return endpoints
    
    async def _test_api_endpoint(self, url: str, client):
        """Testea seguridad de un endpoint de API"""
        
        # 1. Verificar autenticación
        response = await client.get(url)
        self.stats["requests_sent"] += 1
        
        if not response:
            return
        
        # API sin autenticación
        if response.status == 200:
            try:
                data = json.loads(response.text)
                
                # Verificar si expone datos sensibles
                sensitive_keys = ["password", "token", "secret", "key", "api_key", "apikey"]
                found_sensitive = []
                
                def check_dict(d, path=""):
                    if isinstance(d, dict):
                        for k, v in d.items():
                            new_path = f"{path}.{k}" if path else k
                            if any(sk in k.lower() for sk in sensitive_keys):
                                found_sensitive.append(new_path)
                            check_dict(v, new_path)
                    elif isinstance(d, list):
                        for item in d:
                            check_dict(item, path)
                
                check_dict(data)
                
                if found_sensitive:
                    finding = Finding(
                        plugin_name=self.name,
                        severity="CRITICAL",
                        title="API expone datos sensibles sin autenticación",
                        description=f"El endpoint '{url}' retorna datos sin requerir autenticación. "
                                  f"Campos sensibles detectados: {', '.join(found_sensitive[:5])}",
                        url=url,
                        response=response.text[:500],
                        remediation="Implementar autenticación en todos los endpoints de API. "
                                  "Usar OAuth2, JWT o API keys. Nunca exponer credenciales en respuestas.",
                        cwe="CWE-306",
                        cvss_score=9.1
                    )
                    self.add_finding(finding)
                
            except json.JSONDecodeError:
                pass
        
        # 2. Test de métodos HTTP no permitidos
        dangerous_methods = ["PUT", "DELETE", "PATCH"]
        
        for method in dangerous_methods:
            response = await client.request(method, url)
            self.stats["requests_sent"] += 1
            
            if response and response.status in [200, 201, 204]:
                finding = Finding(
                    plugin_name=self.name,
                    severity="HIGH",
                    title=f"API permite método {method} sin autenticación",
                    description=f"El endpoint '{url}' acepta el método {method} sin autenticación aparente.",
                    url=url,
                    payload=method,
                    remediation=f"Deshabilitar método {method} o requerir autenticación fuerte.",
                    cwe="CWE-749",
                    cvss_score=8.2
                )
                self.add_finding(finding)
        
        # 3. Test de IDOR (Insecure Direct Object Reference)
        if "/api/" in url and any(c.isdigit() for c in url):
            # Intentar IDOR simple
            idor_url = re.sub(r'/\d+', '/999999', url)
            
            response_idor = await client.get(idor_url)
            self.stats["requests_sent"] += 1
            
            if response_idor and response_idor.status == 200:
                finding = Finding(
                    plugin_name=self.name,
                    severity="HIGH",
                    title="Posible IDOR en API",
                    description=f"El endpoint parece vulnerable a IDOR. "
                              f"La URL '{idor_url}' retorna datos sin validación de permisos.",
                    url=url,
                    payload=idor_url,
                    remediation="Validar permisos del usuario antes de retornar objetos. "
                              "No confiar en IDs secuenciales.",
                    cwe="CWE-639",
                    cvss_score=7.5
                )
                self.add_finding(finding)
        
        # 4. Verificar rate limiting
        responses = []
        for i in range(10):
            r = await client.get(url)
            if r:
                responses.append(r.status)
        
        self.stats["requests_sent"] += 10
        
        # Si todas las 10 requests tuvieron éxito, no hay rate limiting
        if all(s == 200 for s in responses):
            finding = Finding(
                plugin_name=self.name,
                severity="MEDIUM",
                title="API sin Rate Limiting",
                description=f"El endpoint '{url}' no implementa rate limiting. "
                          f"Se enviaron 10 requests consecutivas sin restricción.",
                url=url,
                remediation="Implementar rate limiting para prevenir abuso y DoS. "
                          "Usar librerías como Flask-Limiter o express-rate-limit.",
                cwe="CWE-770",
                cvss_score=5.3
            )
            self.add_finding(finding)