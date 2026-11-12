# Contributing to WebSecAuditSuite

¡Gracias por tu interés en contribuir a WebSecAuditSuite! 🎉

## 🤝 Cómo Contribuir

### Reportar Bugs

1. Verifica que el bug no haya sido reportado antes en [Issues](https://github.com/RogerF5/WebSecAuditSuite/issues)
2. Crea un nuevo issue con el template de bug report
3. Incluye:
   - Descripción detallada del bug
   - Pasos para reproducir
   - Comportamiento esperado vs actual
   - Screenshots si es posible
   - Logs relevantes
   - Sistema operativo y versión de Python

### Sugerir Nuevas Funcionalidades

1. Abre un issue con el template de feature request
2. Describe claramente:
   - La funcionalidad propuesta
   - Caso de uso / problema que resuelve
   - Implementación sugerida (opcional)

### Pull Requests

1. Fork el repositorio
2. Crea una rama desde `main`:
   ```bash
   git checkout -b feature/nombre-descriptivo
   ```
3. Realiza tus cambios siguiendo las guías de estilo
4. Agrega tests si es aplicable
5. Actualiza la documentación
6. Commit con mensajes descriptivos:
   ```bash
   git commit -m "Add: Nueva funcionalidad X"
   git commit -m "Fix: Corrige bug en plugin Y"
   ```
7. Push a tu fork:
   ```bash
   git push origin feature/nombre-descriptivo
   ```
8. Abre un Pull Request hacia `main`

## 📝 Guías de Estilo

### Python Code Style

- **PEP 8** compliance
- Máximo 100 caracteres por línea
- Docstrings para todas las funciones públicas
- Type hints donde sea posible

```python
def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
    """
    Escanea URL en busca de vulnerabilidades.
    
    Args:
        target_url: URL objetivo del escaneo
        client: Cliente HTTP para realizar requests
        **kwargs: Parámetros adicionales opcionales
    
    Returns:
        Lista de findings encontrados
    """
    pass
```

### Commit Messages

Formato: `<tipo>: <descripción>`

Tipos válidos:
- `Add`: Nueva funcionalidad
- `Fix`: Corrección de bug
- `Update`: Actualización de código existente
- `Refactor`: Refactorización sin cambio funcional
- `Docs`: Cambios en documentación
- `Test`: Añadir o actualizar tests

Ejemplos:
```bash
Add: Plugin de JWT security scanner
Fix: Corrección de encoding UTF-8 en reportes
Update: Mejora performance del directory fuzzer
Docs: Actualiza README con nuevos ejemplos
```

## 🔌 Desarrollar un Nuevo Plugin

### Estructura Base

```python
"""
Plugin de [NOMBRE] - [DESCRIPCIÓN]
"""
from typing import List
from plugins.base_plugin import BasePlugin, Finding
from utils.logger import get_logger

logger = get_logger(__name__)

class MyScanner(BasePlugin):
    """Descripción del scanner"""
    
    def __init__(self):
        super().__init__(
            name="My Scanner",
            description="Scanner para detectar [VULNERABILIDAD]"
        )
        # Tu inicialización aquí
    
    async def scan(self, target_url: str, client, **kwargs) -> List[Finding]:
        """Ejecuta el escaneo"""
        logger.info(f"[MyScanner] Iniciando escaneo en {target_url}")
        
        # Tu lógica de escaneo
        response = await client.get(target_url)
        self.stats["requests_sent"] += 1
        
        # Crear finding si se detecta vulnerabilidad
        if self._is_vulnerable(response):
            finding = Finding(
                plugin_name=self.name,
                severity="HIGH",  # CRITICAL, HIGH, MEDIUM, LOW, INFO
                title="Título descriptivo",
                description="Descripción detallada de la vulnerabilidad",
                url=target_url,
                parameter="param_name",  # Opcional
                payload="payload_usado",  # Opcional
                request=f"GET {target_url}",
                response=response.text[:500],
                remediation="Cómo remediar esta vulnerabilidad",
                cwe="CWE-XXX",  # Opcional
                cvss_score=7.5  # Opcional
            )
            self.add_finding(finding)
        
        logger.info(f"[MyScanner] Escaneo completado. Hallazgos: {len(self.findings)}")
        return self.findings
    
    def _is_vulnerable(self, response) -> bool:
        """Lógica de detección"""
        # Tu implementación
        return False
```

### Registrar el Plugin

En `main.py`:

```python
from plugins.my_scanner import MyScanner

def _register_plugins(self):
    # ...
    self.scanner_engine.register_plugin(MyScanner())
```

### Testing del Plugin

```python
# tests/test_my_scanner.py
import pytest
from plugins.my_scanner import MyScanner

@pytest.mark.asyncio
async def test_scanner_basic():
    scanner = MyScanner()
    # Tu test aquí
```

## 🧪 Testing

### Ejecutar Tests

```bash
# Instalar pytest
pip install pytest pytest-asyncio

# Ejecutar todos los tests
pytest

# Ejecutar tests específicos
pytest tests/test_my_scanner.py

# Con cobertura
pytest --cov=plugins
```

### Escribir Tests

- Un archivo de test por plugin: `tests/test_[plugin_name].py`
- Usar fixtures para setup común
- Tests async para scanners
- Mock de responses HTTP

## 📚 Documentación

### Actualizar README

Si añades un nuevo plugin:

1. Agrégalo a la sección "Plugins Disponibles"
2. Describe brevemente su funcionalidad
3. Añade ejemplo de uso si es relevante

### Docstrings

Todas las funciones públicas deben tener docstrings:

```python
def function(param1: str, param2: int) -> bool:
    """
    Descripción breve de una línea.
    
    Descripción más detallada si es necesario.
    Puede ocupar varias líneas.
    
    Args:
        param1: Descripción del parámetro 1
        param2: Descripción del parámetro 2
    
    Returns:
        Descripción del valor de retorno
    
    Raises:
        ValueError: Cuando param2 es negativo
    """
```

## 🐛 Debugging

### Logs

Usar el logger centralizado:

```python
from utils.logger import get_logger

logger = get_logger(__name__)

logger.debug("Mensaje de debug")
logger.info("Información general")
logger.warning("Advertencia")
logger.error("Error")
```

### Niveles de Log

- `DEBUG`: Información detallada para debugging
- `INFO`: Eventos importantes del flujo normal
- `WARNING`: Situaciones anormales que no impiden ejecución
- `ERROR`: Errores que impiden funcionalidad específica

## ✅ Checklist antes de PR

- [ ] El código sigue PEP 8
- [ ] Agregaste docstrings a funciones nuevas
- [ ] Tests pasan (`pytest`)
- [ ] Actualizaste README si es necesario
- [ ] Commit messages son descriptivos
- [ ] No hay secrets/credentials en el código
- [ ] El código y las dependencias funcionan en el entorno Python 3.11 validado en CI

## 📞 Preguntas

Si tienes preguntas:

1. Revisa la [documentación](README.md)
2. Busca en [Issues existentes](https://github.com/RogerF5/WebSecAuditSuite/issues)
3. Abre un [Discussion](https://github.com/RogerF5/WebSecAuditSuite/discussions)
4. Contacta: roger.f5.security@gmail.com

## 🙏 Agradecimientos

Todos los contribuidores serán reconocidos en el README.

¡Gracias por hacer WebSecAuditSuite mejor! 🚀
