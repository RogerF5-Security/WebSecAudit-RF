"""
Motor de escaneo principal - Coordina todos los plugins
"""
import asyncio
from typing import List, Dict, Optional, Callable
from datetime import datetime
from core.http_client import AdvancedHTTPClient
from plugins.base_plugin import BasePlugin, Finding
from utils.logger import get_logger, log_finding

logger = get_logger(__name__)

class ScannerEngine:
    """Motor principal de escaneo"""
    
    def __init__(self):
        self.plugins: List[BasePlugin] = []
        self.target_url: Optional[str] = None
        self.all_findings: List[Finding] = []
        self.scan_stats = {
            "start_time": None,
            "end_time": None,
            "duration": 0,
            "total_requests": 0,
            "plugins_executed": 0,
            "vulnerabilities_found": 0
        }
        self.progress_callback: Optional[Callable] = None
        self.status_callback: Optional[Callable] = None
        self.stop_flag = False  # Flag para detener escaneo
    
    def register_plugin(self, plugin: BasePlugin):
        """Registra un plugin en el motor"""
        if plugin.enabled:
            self.plugins.append(plugin)
            logger.info(f"Plugin registrado: {plugin.name}")
    
    def set_progress_callback(self, callback: Callable):
        """Establece callback para actualización de progreso"""
        self.progress_callback = callback
    
    def set_status_callback(self, callback: Callable):
        """Establece callback para mensajes de estado"""
        self.status_callback = callback
    
    async def scan(self, target_url: str, proxy: Optional[str] = None) -> Dict:
        """
        Ejecuta escaneo completo
        
        Args:
            target_url: URL objetivo
            proxy: Proxy opcional (http://ip:port)
        
        Returns:
            Diccionario con resultados del escaneo
        """
        self.target_url = target_url
        self.all_findings = []
        self.scan_stats["start_time"] = datetime.now()
        
        logger.info(f"Iniciando escaneo de: {target_url}")
        self._update_status(f"Iniciando escaneo de {target_url}")
        
        # Variable para compartir URLs descubiertas
        discovered_urls = []
        
        async with AdvancedHTTPClient(proxy=proxy) as client:
            total_plugins = len(self.plugins)
            
            for idx, plugin in enumerate(self.plugins):
                # Verificar si se solicitó detener
                if self.stop_flag:
                    logger.warning("Scan detenido por usuario")
                    self._update_status("Scan detenido por usuario")
                    break
                
                logger.info(f"Ejecutando plugin: {plugin.name}")
                self._update_status(f"Ejecutando: {plugin.name}")
                
                try:
                    # Pasar flag de stop al plugin
                    plugin.stop_flag = self.stop_flag
                    
                    # Si es el crawler, guardar URLs descubiertas
                    if plugin.name == "Web Crawler":
                        findings = await plugin.scan(target_url, client)
                        discovered_urls = plugin.get_discovered_urls_with_params()
                    else:
                        # Pasar URLs descubiertas a otros plugins
                        findings = await plugin.scan(target_url, client, discovered_urls=discovered_urls)
                    
                    # Recopilar findings
                    self.all_findings.extend(findings)
                    
                    # Actualizar estadísticas
                    self.scan_stats["total_requests"] += plugin.stats["requests_sent"]
                    self.scan_stats["plugins_executed"] += 1
                    
                    # Log de findings
                    for finding in findings:
                        log_finding(finding.to_dict())
                    
                    # Actualizar progreso
                    progress = ((idx + 1) / total_plugins) * 100
                    self._update_progress(progress)
                    
                except Exception as e:
                    logger.error(f"Error ejecutando plugin {plugin.name}: {str(e)}")
                    self._update_status(f"Error en {plugin.name}: {str(e)}")
        
        # Finalizar
        self.scan_stats["end_time"] = datetime.now()
        self.scan_stats["duration"] = (
            self.scan_stats["end_time"] - self.scan_stats["start_time"]
        ).total_seconds()
        self.scan_stats["vulnerabilities_found"] = len(self.all_findings)
        
        if self.stop_flag:
            logger.info(f"Escaneo detenido. Vulnerabilidades parciales: {len(self.all_findings)}")
            self._update_status("Escaneo detenido por usuario")
        else:
            logger.info(f"Escaneo completado. Vulnerabilidades: {len(self.all_findings)}")
            self._update_status("Escaneo completado")
        
        self._update_progress(100)
        
        return self._generate_results()
    
    def _update_progress(self, value: float):
        """Actualiza progreso vía callback"""
        if self.progress_callback:
            try:
                self.progress_callback(value)
            except Exception as e:
                logger.debug(f"Error en progress_callback: {e}")
    
    def _update_status(self, message: str):
        """Actualiza estado vía callback"""
        if self.status_callback:
            try:
                self.status_callback(message)
            except Exception as e:
                logger.debug(f"Error en status_callback: {e}")
    
    def _generate_results(self) -> Dict:
        """Genera diccionario de resultados"""
        
        # Agrupar por severidad
        findings_by_severity = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": []
        }
        
        for finding in self.all_findings:
            findings_by_severity[finding.severity].append(finding)
        
        # Estadísticas de plugins
        plugin_stats = [plugin.get_stats() for plugin in self.plugins]
        
        return {
            "target": self.target_url,
            "scan_stats": self.scan_stats,
            "findings_by_severity": findings_by_severity,
            "all_findings": self.all_findings,
            "plugin_stats": plugin_stats,
            "summary": {
                "total_vulnerabilities": len(self.all_findings),
                "critical": len(findings_by_severity["CRITICAL"]),
                "high": len(findings_by_severity["HIGH"]),
                "medium": len(findings_by_severity["MEDIUM"]),
                "low": len(findings_by_severity["LOW"]),
                "info": len(findings_by_severity["INFO"])
            }
        }
    
    def get_results(self) -> Dict:
        """Retorna resultados del último escaneo"""
        return self._generate_results()
    
    def clear_results(self):
        """Limpia resultados y findings de todos los plugins"""
        self.all_findings = []
        for plugin in self.plugins:
            plugin.clear_findings()
        logger.info("Resultados limpiados")