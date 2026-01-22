"""
Plugin de fuzzing de directorios y archivos (OPTIMIZADO)
"""
import asyncio
from typing import List
from urllib.parse import urljoin
from pathlib import Path
from plugins.base_plugin import BasePlugin, Finding
from config.settings import PLUGIN_CONFIG
from utils.logger import get_logger

logger = get_logger(__name__)

class DirectoryFuzzer(BasePlugin):
    """Fuzzer de directorios y archivos sensibles"""
    
    def __init__(self):
        super().__init__(
            name="Directory Fuzzer",
            description="Descubre directorios y archivos ocultos mediante fuzzing"
        )
        self.config = PLUGIN_CONFIG["directory_fuzzer"]
        self.wordlist = self._load_wordlist()
        self.extensions = self.config["extensions"]
        self.interesting_codes = self.config["status_codes_interesting"]
        
        # OPTIMIZACIÓN: Limitar número de extensiones por palabra
        self.max_extensions_per_word = 2  # Solo las 2 extensiones más comunes
    
    def _load_wordlist(self) -> List[str]:
        """Carga wordlist desde archivo o usa lista por defecto"""
        wordlist_path = self.config.get("wordlist")
        
        if wordlist_path and Path(wordlist_path).exists():
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.warning(f"Error cargando wordlist: {e}. Usando wordlist por defecto.")
        
        # Wordlist OPTIMIZADA (solo lo más crítico)
        return [
            "admin", "administrator", "login", "signin", "dashboard", "panel",
            "wp-admin", "backup", "config", "db", "database", "api",
            ".git", ".env", ".htaccess", "robots.txt", "sitemap.xml",
            "phpinfo.php", "wp-config.php", "web.config",
            "upload", "uploads", "files", "tmp", "temp", "logs",
            "phpmyadmin", "pma", "debug", "test",
            ".git/config", ".git/HEAD",
            "package.json", "composer.json",
            ".ssh", "id_rsa"
        ]
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Ejecuta fuzzing de directorios"""
        logger.info(f"[Fuzzer] Iniciando fuzzing en {target_url}")
        
        # Asegurar que la URL base termina con /
        base_url = target_url.rstrip('/') + '/'
        
        # Generar lista de URLs a probar (OPTIMIZADA)
        urls_to_test = []
        
        # Solo extensiones más comunes para reducir requests
        common_extensions = ["", ".php", ".html"]
        
        for word in self.wordlist:
            # Path sin extensión
            urls_to_test.append(urljoin(base_url, word))
            
            # Solo 2 extensiones más comunes si el word no tiene extensión
            if "." not in word:
                for ext in common_extensions[:2]:
                    if ext:
                        urls_to_test.append(urljoin(base_url, word + ext))
        
        logger.info(f"[Fuzzer] Probando {len(urls_to_test)} URLs (optimizado)...")
        
        # OPTIMIZACIÓN: Procesar en lotes más pequeños con semáforo
        semaphore = asyncio.Semaphore(20)  # Máximo 20 requests concurrentes
        
        async def bounded_test(url):
            # Verificar stop flag antes de cada request
            if self.stop_flag:
                return
            async with semaphore:
                return await self._test_url(url, client)
        
        # Crear todas las tareas
        tasks = [bounded_test(url) for url in urls_to_test]
        
        # Ejecutar con timeout global
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=120  # Máximo 2 minutos para todo el fuzzing
            )
        except asyncio.TimeoutError:
            logger.warning("[Fuzzer] Fuzzing timeout alcanzado, finalizando...")
        
        logger.info(f"[Fuzzer] Fuzzing completado. Hallazgos: {len(self.findings)}")
        return self.findings
    
    async def _test_url(self, url: str, client):
        """Prueba una URL específica"""
        try:
            # Usar HEAD en lugar de GET para ser más rápido
            response = await client.head(url, allow_redirects=False)
            self.stats["requests_sent"] += 1
            
            if not response:
                return
            
            status = response.status
            
            # Verificar si el código de estado es interesante
            if status in self.interesting_codes:
                severity = self._determine_severity(url, status)
                
                finding = Finding(
                    plugin_name=self.name,
                    severity=severity,
                    title=f"Directorio/Archivo descubierto: {url.split('/')[-1]}",
                    description=f"Se encontró un recurso accesible que puede exponer información sensible. "
                              f"Código de estado: {status}.",
                    url=url,
                    parameter=None,
                    payload=None,
                    request=f"HEAD {url}",
                    response=f"Status: {status}",
                    remediation=self._get_remediation(url),
                    cwe="CWE-548",
                    cvss_score=self._get_cvss_score(url, status)
                )
                self.add_finding(finding)
                logger.info(f"[Fuzzer] ✓ Hallazgo: {url} [{status}]")
        
        except Exception as e:
            logger.debug(f"Error testeando {url}: {e}")
    
    def _determine_severity(self, url: str, status: int) -> str:
        """Determina la severidad basada en la URL y el código de estado"""
        url_lower = url.lower()
        
        # CRITICAL: Archivos de configuración sensibles
        critical_patterns = [
            ".env", "wp-config", "web.config", "database.yml",
            "id_rsa", ".git/config", "passwd", "shadow"
        ]
        if any(pattern in url_lower for pattern in critical_patterns):
            return "CRITICAL"
        
        # HIGH: Paneles administrativos, backups, bases de datos
        high_patterns = [
            "admin", "phpmyadmin", "backup", "sql", "dump",
            ".git", "config", "phpinfo"
        ]
        if any(pattern in url_lower for pattern in high_patterns):
            return "HIGH"
        
        # MEDIUM: Directorios listables, archivos de log
        if status in [200, 301] and any(pattern in url_lower for pattern in ["log", "tmp", "upload"]):
            return "MEDIUM"
        
        # LOW: Otros hallazgos
        return "LOW"
    
    def _get_remediation(self, url: str) -> str:
        """Retorna recomendaciones específicas según el hallazgo"""
        url_lower = url.lower()
        
        if ".git" in url_lower:
            return "Eliminar directorio .git de producción o bloquear acceso mediante .htaccess/nginx config."
        
        if ".env" in url_lower:
            return "Nunca exponer archivos .env. Mover fuera del document root y bloquear en servidor web."
        
        if "admin" in url_lower or "login" in url_lower:
            return "Proteger paneles administrativos con autenticación adicional, IP whitelist y 2FA."
        
        if "backup" in url_lower or "sql" in url_lower:
            return "Eliminar archivos de backup del servidor web. Usar almacenamiento seguro externo."
        
        return "Revisar si este recurso debe ser público. Implementar controles de acceso adecuados."
    
    def _get_cvss_score(self, url: str, status: int) -> float:
        """Calcula score CVSS aproximado"""
        url_lower = url.lower()
        
        if any(pattern in url_lower for pattern in [".env", "id_rsa", "shadow"]):
            return 9.8
        
        if any(pattern in url_lower for pattern in ["admin", "backup", ".git"]):
            return 7.5
        
        if status in [200, 301]:
            return 5.3
        
        return 3.1