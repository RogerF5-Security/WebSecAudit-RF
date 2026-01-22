"""
Cliente HTTP avanzado con evasión de WAF/SOC
"""
import asyncio
import aiohttp
import random
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from config.settings import SCAN_CONFIG, EVASION_CONFIG
from config.user_agents import get_random_headers
from utils.logger import get_logger

logger = get_logger(__name__)

class AdvancedHTTPClient:
    """Cliente HTTP con capacidades de evasión"""
    
    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_count = 0
        self.last_request_time = 0
        
    async def __aenter__(self):
        # Configurar connector con soporte para Brotli
        connector = aiohttp.TCPConnector(
            limit=SCAN_CONFIG["max_concurrent_requests"],
            ssl=False if not SCAN_CONFIG["verify_ssl"] else None,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        
        timeout = aiohttp.ClientTimeout(total=SCAN_CONFIG["request_timeout"])
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            auto_decompress=True  # CRÍTICO: Habilita decompresión automática de Brotli
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _apply_jitter(self):
        """Aplica delay con jitter entre peticiones"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        delay = random.uniform(
            SCAN_CONFIG["delay_min"],
            SCAN_CONFIG["delay_max"]
        )
        
        if elapsed < delay:
            time.sleep(delay - elapsed)
        
        self.last_request_time = time.time()
    
    def _get_headers(self, custom_headers: Optional[Dict] = None) -> Dict:
        """Genera headers con evasión"""
        if EVASION_CONFIG["rotate_user_agents"]:
            headers = get_random_headers()
        else:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        
        # CRÍTICO: Asegurar que aceptamos Brotli
        if "Accept-Encoding" not in headers:
            headers["Accept-Encoding"] = "gzip, deflate, br"
        
        if custom_headers:
            headers.update(custom_headers)
        
        return headers
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        data: Optional[Any] = None,
        params: Optional[Dict] = None,
        allow_redirects: bool = True,
        **kwargs
    ) -> Optional['HTTPResponse']:
        """Ejecuta petición HTTP con evasión"""
        
        if not self.session:
            raise RuntimeError("Cliente no inicializado. Usa 'async with'")
        
        self._apply_jitter()
        
        final_headers = self._get_headers(headers)
        
        try:
            start_time = time.time()
            
            async with self.session.request(
                method=method,
                url=url,
                headers=final_headers,
                data=data,
                params=params,
                allow_redirects=allow_redirects,
                proxy=self.proxy,
                **kwargs
            ) as response:
                self.request_count += 1
                
                # Leer el contenido completo (auto-decomprimido)
                try:
                    content = await response.read()
                    text = content.decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.debug(f"Error decodificando contenido de {url}: {e}")
                    content = b""
                    text = ""
                
                elapsed = time.time() - start_time
                
                # Crear objeto de respuesta personalizado
                resp_obj = HTTPResponse(
                    url=str(response.url),
                    status=response.status,
                    headers=dict(response.headers),
                    content=content,
                    text=text,
                    elapsed=elapsed
                )
                
                logger.debug(f"{method} {url} - Status: {response.status} - Time: {elapsed:.2f}s")
                
                return resp_obj
                
        except asyncio.TimeoutError:
            logger.warning(f"Timeout en {url}")
            return None
        except aiohttp.ClientError as e:
            logger.error(f"Error en petición a {url}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error inesperado en {url}: {str(e)}")
            return None
    
    async def get(self, url: str, **kwargs) -> Optional['HTTPResponse']:
        """GET request"""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Optional['HTTPResponse']:
        """POST request"""
        return await self.request("POST", url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> Optional['HTTPResponse']:
        """HEAD request"""
        return await self.request("HEAD", url, **kwargs)

class HTTPResponse:
    """Objeto de respuesta HTTP estandarizado"""
    
    def __init__(self, url: str, status: int, headers: Dict, content: bytes, text: str, elapsed: float = 0):
        self.url = url
        self.status = status
        self.headers = headers
        self.content = content
        self.text = text
        self.elapsed = elapsed
    
    def json(self):
        """Retorna contenido como JSON"""
        import json
        return json.loads(self.text)

async def test_client():
    """Función de prueba"""
    async with AdvancedHTTPClient() as client:
        # Test con sitio que usa Brotli
        response = await client.get("https://juice-shop.herokuapp.com/")
        if response:
            print(f"Status: {response.status}")
            print(f"Content-Encoding: {response.headers.get('Content-Encoding', 'None')}")
            print(f"Content Length: {len(response.text)} chars")

if __name__ == "__main__":
    asyncio.run(test_client())