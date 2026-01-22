"""
Generador de reportes profesionales en HTML5
"""
import json
from datetime import datetime
from pathlib import Path
from jinja2 import Template
from config.settings import REPORTS_DIR, SEVERITY_LEVELS
from utils.logger import get_logger

logger = get_logger(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Security Audit Report - {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }
        .header {
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            color: white;
            padding: 40px;
            border-radius: 10px 10px 0 0;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .subtitle { opacity: 0.8; font-size: 1.1em; }
        .executive-summary {
            padding: 40px;
            background: #f7fafc;
            border-bottom: 2px solid #e2e8f0;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card .number {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-card .label { color: #718096; text-transform: uppercase; font-size: 0.9em; }
        .severity-CRITICAL .number { color: #d32f2f; }
        .severity-HIGH .number { color: #f57c00; }
        .severity-MEDIUM .number { color: #fbc02d; }
        .severity-LOW .number { color: #388e3c; }
        .findings-section { padding: 40px; }
        .finding-card {
            background: white;
            border-left: 5px solid;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .finding-CRITICAL { border-color: #d32f2f; }
        .finding-HIGH { border-color: #f57c00; }
        .finding-MEDIUM { border-color: #fbc02d; }
        .finding-LOW { border-color: #388e3c; }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .finding-title { font-size: 1.4em; font-weight: bold; }
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }
        .badge-CRITICAL { background: #d32f2f; }
        .badge-HIGH { background: #f57c00; }
        .badge-MEDIUM { background: #fbc02d; color: #333; }
        .badge-LOW { background: #388e3c; }
        .finding-details { margin: 15px 0; line-height: 1.6; }
        .code-block {
            background: #2d3748;
            color: #48bb78;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }
        .remediation {
            background: #edf2f7;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }
        .remediation strong { color: #2d3748; }
        .footer {
            padding: 30px;
            text-align: center;
            background: #2d3748;
            color: white;
            border-radius: 0 0 10px 10px;
        }
        @media print {
            body { background: white; padding: 0; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Web Security Audit Report</h1>
            <div class="subtitle">
                Target: <strong>{{ target }}</strong><br>
                Scan Date: <strong>{{ scan_date }}</strong><br>
                Duration: <strong>{{ duration }}s</strong>
            </div>
        </div>
        
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="label">Total Vulnerabilities</div>
                    <div class="number">{{ summary.total_vulnerabilities }}</div>
                </div>
                <div class="stat-card severity-CRITICAL">
                    <div class="label">Critical</div>
                    <div class="number">{{ summary.critical }}</div>
                </div>
                <div class="stat-card severity-HIGH">
                    <div class="label">High</div>
                    <div class="number">{{ summary.high }}</div>
                </div>
                <div class="stat-card severity-MEDIUM">
                    <div class="label">Medium</div>
                    <div class="number">{{ summary.medium }}</div>
                </div>
                <div class="stat-card severity-LOW">
                    <div class="label">Low</div>
                    <div class="number">{{ summary.low }}</div>
                </div>
            </div>
        </div>
        
        <div class="findings-section">
            <h2>Detailed Findings</h2>
            
            {% for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] %}
                {% if findings_by_severity[severity]|length > 0 %}
                    <h3 style="margin: 30px 0 20px 0;">{{ severity }} Severity</h3>
                    {% for finding in findings_by_severity[severity] %}
                        <div class="finding-card finding-{{ severity }}">
                            <div class="finding-header">
                                <div class="finding-title">{{ finding.title }}</div>
                                <div class="severity-badge badge-{{ severity }}">{{ severity }}</div>
                            </div>
                            <div class="finding-details">
                                <p><strong>Description:</strong> {{ finding.description }}</p>
                                <p><strong>URL:</strong> <code>{{ finding.url }}</code></p>
                                {% if finding.parameter %}
                                    <p><strong>Parameter:</strong> <code>{{ finding.parameter }}</code></p>
                                {% endif %}
                                {% if finding.payload %}
                                    <p><strong>Payload:</strong></p>
                                    <div class="code-block">{{ finding.payload }}</div>
                                {% endif %}
                                {% if finding.cwe %}
                                    <p><strong>CWE:</strong> {{ finding.cwe }} | <strong>CVSS:</strong> {{ finding.cvss_score }}</p>
                                {% endif %}
                            </div>
                            {% if finding.remediation %}
                                <div class="remediation">
                                    <strong>🔧 Remediation:</strong><br>
                                    {{ finding.remediation }}
                                </div>
                            {% endif %}
                        </div>
                    {% endfor %}
                {% endif %}
            {% endfor %}
        </div>
        
        <div class="footer">
            <p>Generated by <strong>WebSecAuditSuite</strong> by Roger F5</p>
            <p>{{ datetime.now().strftime('%Y-%m-%d %H:%M:%S') }}</p>
        </div>
    </div>
</body>
</html>
"""

class ReportGenerator:
    """Generador de reportes HTML profesionales"""
    
    def __init__(self):
        self.template = Template(HTML_TEMPLATE)
    
    def generate_report(self, scan_results: dict, output_filename: str = None) -> Path:
        """
        Genera reporte HTML
        
        Args:
            scan_results: Resultados del escaneo
            output_filename: Nombre del archivo de salida (opcional)
        
        Returns:
            Path del archivo generado
        """
        
        if not output_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"audit_report_{timestamp}.html"
        
        output_path = REPORTS_DIR / output_filename
        
        # Convertir findings a diccionarios
        findings_by_severity_dict = {}
        for severity, findings in scan_results["findings_by_severity"].items():
            findings_by_severity_dict[severity] = [
                f.to_dict() for f in findings
            ]
        
        # Renderizar template
        html_content = self.template.render(
            target=scan_results["target"],
            scan_date=scan_results["scan_stats"]["start_time"].strftime("%Y-%m-%d %H:%M:%S"),
            duration=round(scan_results["scan_stats"]["duration"], 2),
            summary=scan_results["summary"],
            findings_by_severity=findings_by_severity_dict,
            datetime=datetime
        )
        
        # Guardar archivo
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Reporte generado: {output_path}")
        
        # También guardar JSON
        json_path = output_path.with_suffix('.json')
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                "target": scan_results["target"],
                "scan_stats": {
                    **scan_results["scan_stats"],
                    "start_time": scan_results["scan_stats"]["start_time"].isoformat(),
                    "end_time": scan_results["scan_stats"]["end_time"].isoformat()
                },
                "summary": scan_results["summary"],
                "findings": findings_by_severity_dict
            }, f, indent=2, ensure_ascii=False)
        
        return output_path