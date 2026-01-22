"""
Sistema de logging centralizado con formato JSON
"""
import logging
import json
from datetime import datetime
from pathlib import Path
from config.settings import LOGS_DIR

class JSONFormatter(logging.Formatter):
    """Formateador personalizado para logs en JSON"""
    
    def format(self, record):
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Añadir información de excepción si existe
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data, ensure_ascii=False)

def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Retorna un logger configurado
    
    Args:
        name: Nombre del logger (usualmente __name__)
        level: Nivel de logging
    
    Returns:
        Logger configurado
    """
    logger = logging.getLogger(name)
    
    # Evitar duplicar handlers
    if logger.handlers:
        return logger
    
    logger.setLevel(level)
    
    # Handler para archivo
    log_file = LOGS_DIR / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JSONFormatter())
    
    # Handler para consola
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def log_finding(finding_dict: dict):
    """Log específico para findings de vulnerabilidades"""
    findings_log = LOGS_DIR / f"findings_{datetime.now().strftime('%Y%m%d')}.json"
    
    with open(findings_log, 'a', encoding='utf-8') as f:
        json.dump(finding_dict, f, ensure_ascii=False)
        f.write('\n')