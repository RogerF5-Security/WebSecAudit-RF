"""
Plugin de Escaneo Nmap - Detección de vulnerabilidades en infraestructura
"""
import subprocess
import re
import tempfile
import socket
from typing import List
from urllib.parse import urlparse
from pathlib import Path
from plugins.base_plugin import BasePlugin, Finding
from config.settings import REPORTS_DIR
from utils.logger import get_logger

logger = get_logger(__name__)

class NmapScanner(BasePlugin):
    """Scanner Nmap para detección de vulnerabilidades de infraestructura"""
    
    def __init__(self):
        super().__init__(
            name="Nmap Vulnerability Scanner",
            description="Escanea puertos y vulnerabilidades con scripts NSE de Nmap"
        )
        
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 
            587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 
            8888, 27017, 27018, 6379, 11211, 9200, 9300
        ]
        
        self.nmap_available = self._check_nmap()
    
    def _check_nmap(self) -> bool:
        """Verifica si Nmap está instalado"""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info("[Nmap] Nmap encontrado en el sistema")
                return True
        except Exception as e:
            logger.warning(f"[Nmap] Nmap no disponible: {e}")
        
        return False
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Ejecuta escaneo Nmap"""
        
        if not self.nmap_available:
            logger.warning("[Nmap] Nmap no está instalado, saltando escaneo")
            finding = Finding(
                plugin_name=self.name,
                severity="INFO",
                title="Nmap no disponible",
                description="Nmap no está instalado en el sistema. Instalar con: apt install nmap (Linux) o descargar de nmap.org (Windows)",
                url=target_url,
                remediation="Instalar Nmap para habilitar escaneo de vulnerabilidades de infraestructura"
            )
            self.add_finding(finding)
            return self.findings
        
        logger.info(f"[Nmap] Iniciando escaneo de {target_url}")
        
        # Resolver IP del target
        target_ip = self._resolve_ip(target_url)
        
        if not target_ip:
            logger.error(f"[Nmap] No se pudo resolver IP de {target_url}")
            return []
        
        logger.info(f"[Nmap] Target IP: {target_ip}")
        
        # Ejecutar escaneos
        await self._run_nmap_scan(target_ip, target_url)
        
        logger.info(f"[Nmap] Escaneo completado. Vulnerabilidades: {len(self.findings)}")
        return self.findings
    
    def _resolve_ip(self, url: str) -> str:
        """Resuelve hostname a IP"""
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                hostname = url
            
            ip = socket.gethostbyname(hostname)
            return ip
        except Exception as e:
            logger.error(f"Error resolviendo IP: {e}")
            return None
    
    async def _run_nmap_scan(self, target_ip: str, target_url: str):
        """Ejecuta escaneo Nmap con scripts de vulnerabilidad"""
        
        # Crear archivo temporal para output
        nmap_output_file = REPORTS_DIR / f"nmap_scan_{target_ip.replace('.', '_')}.txt"
        
        # Construir comando Nmap
        ports_str = ",".join(map(str, self.common_ports))
        
        cmd = [
            "nmap",
            "-sV",  # Version detection
            "-v",   # Verbose
            "--script=vuln,discovery,http-waf-detect,http-security-headers,ssl-enum-ciphers",
            "-Pn",  # Skip ping
            "-T4",  # Aggressive timing
            "--max-retries", "1",
            "--host-timeout", "10m",
            "-p", ports_str,
            target_ip,
            "-oN", str(nmap_output_file)
        ]
        
        logger.info(f"[Nmap] Ejecutando: {' '.join(cmd)}")
        logger.info("[Nmap] Esto puede tomar varios minutos...")
        
        try:
            # Ejecutar con timeout de 12 minutos
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Esperar con timeout
            try:
                stdout, stderr = process.communicate(timeout=720)  # 12 minutos
            except subprocess.TimeoutExpired:
                process.kill()
                logger.warning("[Nmap] Timeout alcanzado (12 min), finalizando...")
                
                finding = Finding(
                    plugin_name=self.name,
                    severity="INFO",
                    title="Nmap Scan Timeout",
                    description=f"El escaneo Nmap de {target_ip} excedió el tiempo límite de 12 minutos.",
                    url=target_url,
                    remediation="Considerar escaneo manual o aumentar timeout"
                )
                self.add_finding(finding)
                return
            
            # Parsear resultados
            if nmap_output_file.exists():
                self._parse_nmap_output(nmap_output_file, target_url)
            
        except Exception as e:
            logger.error(f"[Nmap] Error ejecutando scan: {e}")
            
            finding = Finding(
                plugin_name=self.name,
                severity="INFO",
                title="Nmap Scan Error",
                description=f"Error ejecutando escaneo Nmap: {str(e)}",
                url=target_url
            )
            self.add_finding(finding)
    
    def _parse_nmap_output(self, output_file: Path, target_url: str):
        """Parsea output de Nmap y extrae vulnerabilidades"""
        
        try:
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 1. Extraer puertos abiertos
            open_ports = re.findall(r'(\d+/tcp)\s+open\s+([^\n]+)', content)
            
            if open_ports:
                ports_desc = "\n".join([f"{p[0]}: {p[1]}" for p in open_ports])
                
                finding = Finding(
                    plugin_name=self.name,
                    severity="INFO",
                    title=f"Puertos Abiertos Detectados ({len(open_ports)})",
                    description=f"Se detectaron {len(open_ports)} puertos abiertos:\n\n{ports_desc}",
                    url=target_url,
                    remediation="Revisar servicios expuestos. Cerrar puertos innecesarios. Implementar firewall.",
                    cwe="CWE-668"
                )
                self.add_finding(finding)
            
            # 2. Extraer vulnerabilidades detectadas por scripts
            vuln_blocks = re.findall(
                r'\|[^\|]*?(?:VULNERABLE:|CVE-\d{4}-\d+).*?(?=\n\d+/|\nNmap|\Z)',
                content,
                re.DOTALL
            )
            
            for block in vuln_blocks:
                # Extraer CVE si existe
                cve_match = re.search(r'CVE-\d{4}-\d+', block)
                cve = cve_match.group(0) if cve_match else None
                
                # Determinar severidad
                severity = "HIGH"
                if "low" in block.lower():
                    severity = "MEDIUM"
                elif "critical" in block.lower():
                    severity = "CRITICAL"
                
                title = cve if cve else "Vulnerabilidad Detectada por Nmap Script"
                
                finding = Finding(
                    plugin_name=self.name,
                    severity=severity,
                    title=title,
                    description=block.strip()[:1000],
                    url=target_url,
                    remediation="Parchear sistema según recomendaciones del CVE. Actualizar software vulnerable.",
                    cwe=cve if cve else "CWE-1035",
                    cvss_score=8.5 if severity == "CRITICAL" else 7.0
                )
                self.add_finding(finding)
                logger.info(f"[Nmap] ✓ Vulnerabilidad detectada: {title}")
            
            # 3. Detectar WAF
            if "http-waf-detect" in content:
                waf_match = re.search(r'http-waf-detect:.*?\n(.*?)(?=\n\||$)', content, re.DOTALL)
                if waf_match:
                    waf_info = waf_match.group(1).strip()
                    
                    finding = Finding(
                        plugin_name=self.name,
                        severity="INFO",
                        title="WAF Detectado",
                        description=f"Se detectó un Web Application Firewall:\n{waf_info}",
                        url=target_url,
                        remediation="El sitio tiene WAF. Considerar técnicas de evasión en testing."
                    )
                    self.add_finding(finding)
            
            # 4. Headers de seguridad
            headers_match = re.search(r'http-security-headers:(.*?)(?=\n\d+/|\nNmap|\Z)', content, re.DOTALL)
            if headers_match:
                headers_info = headers_match.group(1).strip()
                
                # Solo reportar si hay headers faltantes
                if "Missing" in headers_info or "missing" in headers_info:
                    finding = Finding(
                        plugin_name=self.name,
                        severity="LOW",
                        title="Headers de Seguridad Faltantes (Nmap)",
                        description=f"Nmap detectó headers de seguridad faltantes:\n{headers_info[:500]}",
                        url=target_url,
                        remediation="Implementar headers de seguridad según best practices"
                    )
                    self.add_finding(finding)
            
            # 5. SSL/TLS debilidades
            if "ssl-enum-ciphers" in content:
                ssl_weak = re.search(r'(SSLv[23]|TLSv1\.0|weak|RC4|MD5)', content, re.IGNORECASE)
                
                if ssl_weak:
                    finding = Finding(
                        plugin_name=self.name,
                        severity="MEDIUM",
                        title="Configuración SSL/TLS Débil",
                        description="Nmap detectó configuraciones SSL/TLS débiles o protocolos obsoletos.",
                        url=target_url,
                        remediation="Deshabilitar SSLv2, SSLv3, TLSv1.0. Usar solo TLSv1.2+. Deshabilitar ciphers débiles.",
                        cwe="CWE-327",
                        cvss_score=5.3
                    )
                    self.add_finding(finding)
            
            logger.info(f"[Nmap] Reporte guardado en: {output_file}")
            
        except Exception as e:
            logger.error(f"[Nmap] Error parseando output: {e}")