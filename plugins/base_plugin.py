"""
Clase base para plugins de escaneo
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class Finding:
    """Estructura de una vulnerabilidad encontrada"""
    plugin_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    remediation: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte finding a diccionario"""
        return {
            "plugin": self.plugin_name,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "request": self.request[:500] if self.request else None,  # Truncar
            "response": self.response[:500] if self.response else None,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "timestamp": self.timestamp.isoformat()
        }

class BasePlugin(ABC):
    """Clase base abstracta para todos los plugins"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.enabled = True
        self.findings: List[Finding] = []
        self.stop_flag = False  # Flag para detener el plugin
        self.stats = {
            "requests_sent": 0,
            "vulnerabilities_found": 0,
            "scan_time": 0
        }
    
    @abstractmethod
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """
        Método principal de escaneo - DEBE ser implementado
        
        Args:
            target_url: URL objetivo
            client: Instancia de AdvancedHTTPClient
            **kwargs: Parámetros adicionales
            
        Returns:
            Lista de findings encontrados
        """
        pass
    
    def add_finding(self, finding: Finding):
        """Añade un finding a la lista"""
        self.findings.append(finding)
        self.stats["vulnerabilities_found"] += 1
        logger.info(
            f"[{self.name}] Vulnerabilidad encontrada: {finding.severity} - {finding.title}"
        )
    
    def get_findings(self, severity: Optional[str] = None) -> List[Finding]:
        """Obtiene findings, opcionalmente filtrados por severidad"""
        if severity:
            return [f for f in self.findings if f.severity == severity]
        return self.findings
    
    def clear_findings(self):
        """Limpia todos los findings"""
        self.findings = []
        self.stats["vulnerabilities_found"] = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estadísticas del plugin"""
        return {
            "name": self.name,
            "enabled": self.enabled,
            **self.stats
        }
    
    def __repr__(self):
        return f"<{self.__class__.__name__} name='{self.name}' findings={len(self.findings)}>"