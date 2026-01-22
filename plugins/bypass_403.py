"""
Plugin de Bypass 403 Forbidden - Técnicas avanzadas de evasión WAF
"""
import asyncio
from typing import List
from urllib.parse import urljoin, quote
from pathlib import Path
from plugins.base_plugin import BasePlugin, Finding
from config.settings import BASE_DIR
from utils.logger import get_logger

logger = get_logger(__name__)

class Bypass403Scanner(BasePlugin):
    """Scanner de técnicas de bypass para 403 Forbidden"""
    
    def __init__(self):
        super().__init__(
            name="403 Bypass Scanner",
            description="Intenta evadir restricciones 403 con múltiples técnicas"
        )
        self.payloads = self._load_payloads()
        self.bypass_headers = self._get_bypass_headers()
    
    def _load_payloads(self) -> List[dict]:
        """Carga payloads desde archivo"""
        wordlist_path = BASE_DIR / "data" / "wordlists" / "403bypass.txt"
        payloads = []
        
        if wordlist_path.exists():
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        # Parsear payload
                        payload_data = self._parse_payload(line)
                        if payload_data:
                            payloads.append(payload_data)
                
                logger.info(f"[403Bypass] Cargados {len(payloads)} payloads")
            except Exception as e:
                logger.warning(f"Error cargando 403bypass.txt: {e}")
        
        if not payloads:
            # Payloads por defecto si no hay archivo
            payloads = [
                {"path": "admin", "method": "GET", "headers": {}},
                {"path": "%2e/admin", "method": "GET", "headers": {}},
                {"path": "admin/.", "method": "GET", "headers": {}},
                {"path": "/admin//", "method": "GET", "headers": {}}
            ]
        
        return payloads
    
    def _parse_payload(self, line: str) -> dict:
        """Parsea una línea del wordlist a estructura de payload"""
        parts = line.split()
        payload = {
            "path": parts[0],
            "method": "GET",
            "headers": {}
        }
        
        # Parsear headers adicionales (-H)
        i = 1
        while i < len(parts):
            if parts[i] == "-H" and i + 1 < len(parts):
                header_str = parts[i + 1]
                if ":" in header_str:
                    key, value = header_str.split(":", 1)
                    payload["headers"][key.strip()] = value.strip()
                i += 2
            elif parts[i] == "-X" and i + 1 < len(parts):
                payload["method"] = parts[i + 1]
                i += 2
            else:
                i += 1
        
        return payload
    
    def _get_bypass_headers(self) -> List[dict]:
        """Headers comunes para bypass"""
        return [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "127.0.0.1"},
            {"X-Host": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"Cluster-Client-IP": "127.0.0.1"},
            {"X-ProxyUser-Ip": "127.0.0.1"},
            {"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=127.0.0.1"}
        ]
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Escanea en busca de bypasses 403"""
        logger.info(f"[403Bypass] Iniciando escaneo de bypass en {target_url}")
        
        # Primero identificar recursos 403
        forbidden_resources = await self._find_forbidden_resources(target_url, client)
        
        if not forbidden_resources:
            logger.info("[403Bypass] No se encontraron recursos 403 para testear")
            return []
        
        logger.info(f"[403Bypass] Encontrados {len(forbidden_resources)} recursos 403, probando bypasses...")
        
        # Intentar bypass en cada recurso
        for resource in forbidden_resources:
            await self._attempt_bypass(resource, client)
        
        logger.info(f"[403Bypass] Escaneo completado. Bypasses exitosos: {len(self.findings)}")
        return self.findings
    
    async def _find_forbidden_resources(self, base_url: str, client) -> List[str]:
        """Encuentra recursos que retornan 403"""
        forbidden = []
        common_paths = [
            "/admin", "/administrator", "/panel", "/dashboard",
            "/wp-admin", "/phpmyadmin", "/backup", "/config"
        ]
        
        base_url = base_url.rstrip('/')
        
        for path in common_paths:
            url = base_url + path
            response = await client.get(url)
            self.stats["requests_sent"] += 1
            
            if response and response.status == 403:
                forbidden.append(url)
                logger.info(f"[403Bypass] ✓ Recurso 403 encontrado: {url}")
        
        return forbidden
    
    async def _attempt_bypass(self, forbidden_url: str, client):
        """Intenta múltiples técnicas de bypass en un recurso 403"""
        
        # 1. Bypass con path variations
        await self._test_path_variations(forbidden_url, client)
        
        # 2. Bypass con headers
        await self._test_header_bypass(forbidden_url, client)
        
        # 3. Bypass con métodos HTTP
        await self._test_method_bypass(forbidden_url, client)
    
    async def _test_path_variations(self, url: str, client):
        """Prueba variaciones de path"""
        base_path = url.split('/')[-1]
        base_url = url.rsplit('/', 1)[0]
        
        variations = [
            f"{base_path}/.",
            f"{base_path}//",
            f"./{base_path}/./",
            f"{base_path}%20",
            f"{base_path}%09",
            f"{base_path}?",
            f"{base_path}.html",
            f"{base_path}/*",
            f"{base_path}..;/",
            f"{base_path};/",
            f"%2e/{base_path}",
            f"{base_path}/.."
        ]
        
        for variation in variations:
            test_url = f"{base_url}/{variation}"
            
            response = await client.get(test_url)
            self.stats["requests_sent"] += 1
            
            if response and response.status == 200:
                finding = Finding(
                    plugin_name=self.name,
                    severity="HIGH",
                    title=f"403 Bypass exitoso mediante path variation",
                    description=f"Se logró evadir la restricción 403 en '{url}' usando la variación '{variation}'. "
                              f"Código de estado obtenido: {response.status}",
                    url=test_url,
                    parameter=None,
                    payload=variation,
                    request=f"GET {test_url}",
                    response=response.text[:500],
                    remediation="Implementar validación consistente de paths. Normalizar URLs antes de aplicar ACLs. "
                              "Usar middleware que maneje todas las variaciones de path.",
                    cwe="CWE-639",
                    cvss_score=7.5
                )
                self.add_finding(finding)
                logger.info(f"[403Bypass] ✓✓ BYPASS EXITOSO: {test_url}")
    
    async def _test_header_bypass(self, url: str, client):
        """Prueba bypass mediante headers"""
        
        for header_set in self.bypass_headers:
            response = await client.get(url, headers=header_set)
            self.stats["requests_sent"] += 1
            
            if response and response.status == 200:
                header_name = list(header_set.keys())[0]
                
                finding = Finding(
                    plugin_name=self.name,
                    severity="HIGH",
                    title=f"403 Bypass exitoso mediante header '{header_name}'",
                    description=f"Se logró evadir la restricción 403 en '{url}' usando el header '{header_name}'. "
                              f"Esto indica que el servidor confía en headers HTTP controlables por el cliente.",
                    url=url,
                    parameter=header_name,
                    payload=str(header_set),
                    request=f"GET {url}\n{header_name}: {header_set[header_name]}",
                    response=response.text[:500],
                    remediation="No confiar en headers HTTP para control de acceso. "
                              f"Validar que {header_name} no se use para autorización. "
                              "Implementar ACLs independientes de headers de forwarding.",
                    cwe="CWE-290",
                    cvss_score=8.1
                )
                self.add_finding(finding)
                logger.info(f"[403Bypass] ✓✓ BYPASS EXITOSO con header: {header_name}")
    
    async def _test_method_bypass(self, url: str, client):
        """Prueba bypass mediante métodos HTTP alternativos"""
        
        methods = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"]
        
        for method in methods:
            response = await client.request(method, url)
            self.stats["requests_sent"] += 1
            
            if response and response.status in [200, 201, 204]:
                finding = Finding(
                    plugin_name=self.name,
                    severity="MEDIUM",
                    title=f"403 Bypass exitoso mediante método {method}",
                    description=f"Se logró evadir la restricción 403 en '{url}' usando el método HTTP '{method}'. "
                              f"El recurso retornó código {response.status} en lugar de 403.",
                    url=url,
                    parameter="HTTP Method",
                    payload=method,
                    request=f"{method} {url}",
                    response=response.text[:500],
                    remediation=f"Aplicar ACLs consistentes para todos los métodos HTTP. "
                              f"Deshabilitar métodos {method} si no son necesarios.",
                    cwe="CWE-436",
                    cvss_score=6.5
                )
                self.add_finding(finding)
                logger.info(f"[403Bypass] ✓✓ BYPASS EXITOSO con método: {method}")