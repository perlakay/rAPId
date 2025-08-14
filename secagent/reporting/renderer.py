"""
AI-powered security report generation.
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader, Template
from rich.console import Console

console = Console()

class ReportRenderer:
    """AI-powered security report renderer."""
    
    def __init__(self, run_dir: Path, ollama_client, verbose: bool = False):
        self.run_dir = run_dir
        self.ollama_client = ollama_client
        self.verbose = verbose
        
        # Ensure Ollama is available for hackathon
        if not self.ollama_client or not self.ollama_client.is_available():
            raise Exception(
                "🤖 AI (Ollama) is required for this hackathon project!\n"
                "Please install and start Ollama:\n"
                "  brew install ollama\n"
                "  ollama pull llama3\n"
                "  ollama serve"
            )
        
        # Setup Jinja2 templates
        self.template_dir = Path(__file__).parent / "templates"
        self.template_dir.mkdir(exist_ok=True)
        
        # Create templates if they don't exist
        self._ensure_templates_exist()
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
    
    def generate_reports(self, target_info: Dict[str, Any], static_results: Dict[str, Any],
                        endpoints: List[Dict[str, Any]], test_results: List[Dict[str, Any]],
                        report_formats: List[str]) -> List[Path]:
        """Generate AI-powered security reports."""
        
        if self.verbose:
            console.print("   🤖 Generating AI-powered security analysis...")
        
        # Step 1: Prepare data for AI analysis
        analysis_data = self._prepare_analysis_data(
            target_info, static_results, endpoints, test_results
        )
        
        # Step 2: Generate AI insights
        ai_insights = self._generate_ai_insights(analysis_data)
        
        # Step 3: Prepare report context
        report_context = self._prepare_report_context(
            target_info, static_results, endpoints, test_results, ai_insights
        )
        
        # Step 4: Generate reports in requested formats
        generated_files = []
        
        if "md" in report_formats or "both" in report_formats:
            md_file = self._generate_markdown_report(report_context)
            generated_files.append(md_file)
        
        if "html" in report_formats or "both" in report_formats:
            html_file = self._generate_html_report(report_context)
            generated_files.append(html_file)
        
        return generated_files
    
    def _prepare_analysis_data(self, target_info: Dict[str, Any], static_results: Dict[str, Any],
                              endpoints: List[Dict[str, Any]], test_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare data for AI analysis."""
        
        # Calculate statistics
        vulnerable_results = [r for r in test_results if r.get("status") == "vulnerable"]
        
        stats = {
            "total_endpoints": len(endpoints),
            "total_tests": len(test_results),
            "vulnerable_count": len(vulnerable_results),
            "high_severity": len([r for r in vulnerable_results if r.get("severity") == "high"]),
            "medium_severity": len([r for r in vulnerable_results if r.get("severity") == "medium"]),
            "low_severity": len([r for r in vulnerable_results if r.get("severity") == "low"]),
            "technologies": static_results.get("technologies", []),
            "discovery_methods": static_results.get("discovery_methods", [])
        }
        
        # Top vulnerabilities for AI analysis
        top_vulnerabilities = sorted(
            vulnerable_results,
            key=lambda x: {"high": 3, "medium": 2, "low": 1}.get(x.get("severity", "low"), 0),
            reverse=True
        )[:10]
        
        return {
            "stats": stats,
            "vulnerabilities": top_vulnerabilities,
            "endpoints": endpoints[:20],  # Sample for AI analysis
            "findings": static_results.get("security_findings", [])[:10]
        }
    
    def _generate_ai_insights(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-powered security insights."""
        
        if self.verbose:
            console.print("   🧠 Generating executive summary...")
        
        insights = {}
        
        try:
            # Executive summary
            insights["executive_summary"] = self.ollama_client.generate_summary(analysis_data)
            
            if self.verbose:
                console.print("   🔍 Analyzing vulnerability patterns...")
            
            # Vulnerability pattern analysis
            if analysis_data["vulnerabilities"]:
                insights["pattern_analysis"] = self.ollama_client.analyze_vulnerability_pattern(
                    analysis_data["vulnerabilities"]
                )
            else:
                insights["pattern_analysis"] = "No vulnerabilities detected for pattern analysis."
            
            if self.verbose:
                console.print("   💡 Generating security recommendations...")
            
            # Security recommendations
            insights["recommendations"] = self.ollama_client.generate_security_recommendations({
                "endpoints": analysis_data["endpoints"],
                "technologies": analysis_data["stats"]["technologies"],
                "findings": analysis_data["findings"]
            })
            
            # Individual vulnerability explanations
            if self.verbose:
                console.print("   📝 Generating vulnerability explanations...")
            
            insights["vulnerability_explanations"] = {}
            for vuln in analysis_data["vulnerabilities"][:5]:  # Top 5 vulnerabilities
                vuln_id = vuln.get("id", "unknown")
                try:
                    explanation = self.ollama_client.generate_remediation(vuln)
                    insights["vulnerability_explanations"][vuln_id] = explanation
                except Exception as e:
                    insights["vulnerability_explanations"][vuln_id] = f"AI explanation failed: {e}"
            
        except Exception as e:
            raise Exception(f"🤖 AI analysis failed: {e}")
        
        return insights
    
    def _prepare_report_context(self, target_info: Dict[str, Any], static_results: Dict[str, Any],
                               endpoints: List[Dict[str, Any]], test_results: List[Dict[str, Any]],
                               ai_insights: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare comprehensive report context."""
        
        # Categorize results
        vulnerable_results = [r for r in test_results if r.get("status") == "vulnerable"]
        secure_results = [r for r in test_results if r.get("status") == "secure"]
        error_results = [r for r in test_results if r.get("status") == "error"]
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for result in vulnerable_results:
            test_type = result.get("test_type", "unknown")
            if test_type not in vuln_by_type:
                vuln_by_type[test_type] = []
            vuln_by_type[test_type].append(result)
        
        # Calculate risk score (AI-enhanced)
        risk_score = self._calculate_ai_risk_score(vulnerable_results, ai_insights)
        
        return {
            "target_info": target_info,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ai_insights": ai_insights,
            "statistics": {
                "total_endpoints": len(endpoints),
                "total_tests": len(test_results),
                "vulnerable_count": len(vulnerable_results),
                "secure_count": len(secure_results),
                "error_count": len(error_results),
                "risk_score": risk_score,
                "severity_breakdown": {
                    "high": len([r for r in vulnerable_results if r.get("severity") == "high"]),
                    "medium": len([r for r in vulnerable_results if r.get("severity") == "medium"]),
                    "low": len([r for r in vulnerable_results if r.get("severity") == "low"])
                }
            },
            "endpoints": endpoints,
            "vulnerabilities": vulnerable_results,
            "vulnerabilities_by_type": vuln_by_type,
            "static_findings": static_results.get("security_findings", []),
            "technologies": static_results.get("technologies", []),
            "discovery_methods": static_results.get("discovery_methods", []),
            "metadata": static_results.get("metadata", {})
        }
    
    def _calculate_ai_risk_score(self, vulnerabilities: List[Dict[str, Any]], 
                                ai_insights: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate AI-enhanced risk score."""
        
        if not vulnerabilities:
            return {"score": 0, "level": "LOW", "description": "No vulnerabilities detected"}
        
        # Base scoring
        high_count = len([v for v in vulnerabilities if v.get("severity") == "high"])
        medium_count = len([v for v in vulnerabilities if v.get("severity") == "medium"])
        low_count = len([v for v in vulnerabilities if v.get("severity") == "low"])
        
        base_score = (high_count * 10) + (medium_count * 5) + (low_count * 1)
        
        # AI enhancement factor (based on pattern analysis)
        ai_factor = 1.0
        pattern_analysis = ai_insights.get("pattern_analysis", "").lower()
        
        if "systemic" in pattern_analysis or "widespread" in pattern_analysis:
            ai_factor = 1.5
        elif "isolated" in pattern_analysis or "limited" in pattern_analysis:
            ai_factor = 0.8
        
        final_score = min(100, int(base_score * ai_factor))
        
        if final_score >= 70:
            level = "CRITICAL"
        elif final_score >= 40:
            level = "HIGH"
        elif final_score >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"
        
        return {
            "score": final_score,
            "level": level,
            "description": f"AI-enhanced risk assessment based on {len(vulnerabilities)} vulnerabilities"
        }
    
    def _generate_markdown_report(self, context: Dict[str, Any]) -> Path:
        """Generate Markdown report."""
        template = self.jinja_env.get_template("report.md.j2")
        content = template.render(**context)
        
        report_file = self.run_dir / "report.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        if self.verbose:
            console.print(f"   📄 Generated Markdown report: {report_file}")
        
        return report_file
    
    def _generate_html_report(self, context: Dict[str, Any]) -> Path:
        """Generate HTML report."""
        template = self.jinja_env.get_template("report.html.j2")
        content = template.render(**context)
        
        report_file = self.run_dir / "report.html"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        if self.verbose:
            console.print(f"   🌐 Generated HTML report: {report_file}")
        
        return report_file
    
    def _ensure_templates_exist(self):
        """Create report templates if they don't exist."""
        
        # Markdown template
        md_template_path = self.template_dir / "report.md.j2"
        if not md_template_path.exists():
            self._create_markdown_template(md_template_path)
        
        # HTML template
        html_template_path = self.template_dir / "report.html.j2"
        if not html_template_path.exists():
            self._create_html_template(html_template_path)
    
    def _create_markdown_template(self, template_path: Path):
        """Create Markdown report template."""
        template_content = '''# 🛡️ AI-Powered API Security Assessment Report

**Target:** {{ target_info.base_url }}  
**Repository:** {{ target_info.repo }}  
**Generated:** {{ timestamp }}  
**Risk Level:** {{ statistics.risk_score.level }} ({{ statistics.risk_score.score }}/100)

---

## 🤖 AI Executive Summary

{{ ai_insights.executive_summary }}

---

## 📊 Assessment Overview

| Metric | Count |
|--------|-------|
| **Total Endpoints** | {{ statistics.total_endpoints }} |
| **Security Tests** | {{ statistics.total_tests }} |
| **Vulnerabilities Found** | {{ statistics.vulnerable_count }} |
| **High Severity** | {{ statistics.severity_breakdown.high }} |
| **Medium Severity** | {{ statistics.severity_breakdown.medium }} |
| **Low Severity** | {{ statistics.severity_breakdown.low }} |

**Technologies Detected:** {{ technologies | join(", ") }}  
**Discovery Methods:** {{ discovery_methods | join(", ") }}

---

## 🔍 AI Vulnerability Pattern Analysis

{{ ai_insights.pattern_analysis }}

---

## ⚠️ Critical Vulnerabilities

{% for vuln in vulnerabilities %}
{% if vuln.severity == "high" %}
### {{ vuln.test_name }}

**Endpoint:** `{{ vuln.request_data.method }} {{ vuln.request_data.url }}`  
**Severity:** {{ vuln.severity.upper() }}  
**Status:** {{ vuln.status.upper() }}

**AI Remediation:**
{% if ai_insights.vulnerability_explanations[vuln.id] %}
{{ ai_insights.vulnerability_explanations[vuln.id] }}
{% else %}
Standard remediation practices apply for {{ vuln.test_type }} vulnerabilities.
{% endif %}

**Evidence:**
```json
{{ vuln.evidence | tojson(indent=2) }}
```

---
{% endif %}
{% endfor %}

## 💡 AI Security Recommendations

{{ ai_insights.recommendations }}

---

## 📋 All Endpoints Analyzed

| Method | Path | Auth | Security Hints |
|--------|------|------|----------------|
{% for endpoint in endpoints %}
| {{ endpoint.method }} | `{{ endpoint.path }}` | {{ "✅" if endpoint.auth_detected else "❌" }} | {{ endpoint.security_hints | join(", ") }} |
{% endfor %}

---

## 🔧 Technical Details

### Static Analysis Findings
{% for finding in static_findings %}
- **{{ finding.type }}** ({{ finding.severity }}): {{ finding.message }}
{% endfor %}

### Test Results Summary
- **Vulnerable:** {{ statistics.vulnerable_count }}
- **Secure:** {{ statistics.secure_count }}
- **Errors:** {{ statistics.error_count }}

---

*Report generated by AI-Powered Security Agent*
'''
        
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)
    
    def _create_html_template(self, template_path: Path):
        """Create HTML report template."""
        template_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ AI Security Assessment Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }
        .content { padding: 30px; }
        .ai-section { background: #f8f9ff; border-left: 4px solid #667eea; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .risk-badge { display: inline-block; padding: 8px 16px; border-radius: 20px; font-weight: bold; margin: 10px 0; }
        .risk-critical { background: #ff4757; color: white; }
        .risk-high { background: #ff6b7a; color: white; }
        .risk-medium { background: #ffa726; color: white; }
        .risk-low { background: #66bb6a; color: white; }
        .vuln-card { border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; margin: 15px 0; }
        .vuln-high { border-left: 4px solid #ff4757; }
        .vuln-medium { border-left: 4px solid #ffa726; }
        .vuln-low { border-left: 4px solid #66bb6a; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #667eea; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Monaco', monospace; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .emoji { font-size: 1.2em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AI-Powered API Security Assessment</h1>
            <p><strong>Target:</strong> {{ target_info.base_url }}</p>
            <p><strong>Repository:</strong> {{ target_info.repo }}</p>
            <p><strong>Generated:</strong> {{ timestamp }}</p>
            <div class="risk-badge risk-{{ statistics.risk_score.level.lower() }}">
                Risk Level: {{ statistics.risk_score.level }} ({{ statistics.risk_score.score }}/100)
            </div>
        </div>
        
        <div class="content">
            <div class="ai-section">
                <h2>🤖 AI Executive Summary</h2>
                <p>{{ ai_insights.executive_summary }}</p>
            </div>
            
            <h2>📊 Assessment Overview</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.total_endpoints }}</div>
                    <div>Endpoints</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.vulnerable_count }}</div>
                    <div>Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.severity_breakdown.high }}</div>
                    <div>High Severity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.total_tests }}</div>
                    <div>Tests Run</div>
                </div>
            </div>
            
            <div class="ai-section">
                <h2>🔍 AI Vulnerability Pattern Analysis</h2>
                <p>{{ ai_insights.pattern_analysis }}</p>
            </div>
            
            <h2>⚠️ Vulnerabilities Found</h2>
            {% for vuln in vulnerabilities %}
            <div class="vuln-card vuln-{{ vuln.severity }}">
                <h3>{{ vuln.test_name }}</h3>
                <p><strong>Endpoint:</strong> <code>{{ vuln.request_data.method }} {{ vuln.request_data.url }}</code></p>
                <p><strong>Severity:</strong> {{ vuln.severity.upper() }}</p>
                
                {% if ai_insights.vulnerability_explanations[vuln.id] %}
                <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 10px 0;">
                    <strong>🤖 AI Remediation:</strong><br>
                    {{ ai_insights.vulnerability_explanations[vuln.id] }}
                </div>
                {% endif %}
                
                <details>
                    <summary>Technical Evidence</summary>
                    <pre>{{ vuln.evidence | tojson(indent=2) }}</pre>
                </details>
            </div>
            {% endfor %}
            
            <div class="ai-section">
                <h2>💡 AI Security Recommendations</h2>
                <p>{{ ai_insights.recommendations }}</p>
            </div>
            
            <h2>📋 Endpoint Inventory</h2>
            <table>
                <thead>
                    <tr>
                        <th>Method</th>
                        <th>Path</th>
                        <th>Auth</th>
                        <th>Security Hints</th>
                    </tr>
                </thead>
                <tbody>
                    {% for endpoint in endpoints %}
                    <tr>
                        <td><code>{{ endpoint.method }}</code></td>
                        <td><code>{{ endpoint.path }}</code></td>
                        <td>{{ "✅" if endpoint.auth_detected else "❌" }}</td>
                        <td>{{ endpoint.security_hints | join(", ") }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <h2>🔧 Technical Details</h2>
            <p><strong>Technologies:</strong> {{ technologies | join(", ") }}</p>
            <p><strong>Discovery Methods:</strong> {{ discovery_methods | join(", ") }}</p>
            
            {% if static_findings %}
            <h3>Static Analysis Findings</h3>
            <ul>
                {% for finding in static_findings %}
                <li><strong>{{ finding.type }}</strong> ({{ finding.severity }}): {{ finding.message }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
    </div>
</body>
</html>'''
        
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)
