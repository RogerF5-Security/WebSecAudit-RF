"""
Plugin Crawler - Descubre URLs con parámetros en el sitio
"""
import asyncio
from typing import List, Set
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from plugins.base_plugin import BasePlugin, Finding
from utils.logger import get_logger

logger = get_logger(__name__)

class WebCrawler(BasePlugin):
    """Crawler para descubrir URLs con parámetros"""
    
    def __init__(self):
        super().__init__(
            name="Web Crawler",
            description="Descubre URLs con parámetros para testing de inyecciones"
        )
        self.discovered_urls: Set[str] = set()
        self.urls_with_params: List[str] = []
        self.max_depth = 2
        self.max_urls = 50
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Crawlea el sitio para descubrir URLs con parámetros"""
        logger.info(f"[Crawler] Iniciando crawling de {target_url}")
        
        base_domain = urlparse(target_url).netloc
        
        # Comenzar crawling
        await self._crawl_recursive(target_url, base_domain, client, depth=0)
        
        logger.info(f"[Crawler] Crawling completado. URLs descubiertas: {len(self.discovered_urls)}")
        logger.info(f"[Crawler] URLs con parámetros: {len(self.urls_with_params)}")
        
        # Guardar URLs con parámetros para otros plugins
        if hasattr(client, 'discovered_params_urls'):
            client.discovered_params_urls = self.urls_with_params
        
        # Este plugin no genera findings, solo descubre URLs
        return []
    
    async def _crawl_recursive(self, url: str, base_domain: str, client, depth: int):
        """Crawlea recursivamente hasta max_depth"""
        
        if depth > self.max_depth:
            return
        
        if len(self.discovered_urls) >= self.max_urls:
            return
        
        if url in self.discovered_urls:
            return
        
        self.discovered_urls.add(url)
        logger.debug(f"[Crawler] Crawling: {url} (depth: {depth})")
        
        try:
            response = await client.get(url)
            self.stats["requests_sent"] += 1
            
            if not response or response.status != 200:
                return
            
            # Verificar si la URL tiene parámetros
            if parse_qs(urlparse(url).query):
                self.urls_with_params.append(url)
                logger.info(f"[Crawler] ✓ URL con parámetros: {url}")
            
            # Parsear HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extraer links
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Construir URL absoluta
                absolute_url = urljoin(url, href)
                parsed = urlparse(absolute_url)
                
                # Solo crawlear mismo dominio
                if parsed.netloc != base_domain:
                    continue
                
                # Ignorar anchors y javascript
                if parsed.fragment or absolute_url.startswith('javascript:'):
                    continue
                
                # Crawlear recursivamente
                await self._crawl_recursive(absolute_url, base_domain, client, depth + 1)
        
        except Exception as e:
            logger.debug(f"[Crawler] Error en {url}: {e}")
    
    def get_discovered_urls_with_params(self) -> List[str]:
        """Retorna lista de URLs con parámetros descubiertas"""
        return self.urls_with_params