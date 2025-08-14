"""
Ollama LLM client for enhanced security reporting.
"""

import json
from typing import Dict, Any, Optional, List
import httpx
from rich.console import Console

console = Console()

class OllamaClient:
    """Client for interacting with Ollama local LLM."""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3"):
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.available = None  # Cache availability check
    
    def is_available(self) -> bool:
        """Check if Ollama is available and responsive."""
        if self.available is not None:
            return self.available
        
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.base_url}/api/tags")
                self.available = response.status_code == 200
                return self.available
        except Exception:
            self.available = False
            return False
    
    def generate_remediation(self, vulnerability: Dict[str, Any]) -> str:
        """Generate remediation advice for a vulnerability."""
        if not self.is_available():
            return self._fallback_remediation(vulnerability)
        
        prompt = self._create_remediation_prompt(vulnerability)
        
        try:
            response = self._generate(prompt)
            if response and len(response.strip()) > 50:
                return response.strip()
        except Exception as e:
            console.print(f"   ⚠️  Ollama generation failed: {e}", style="yellow")
        
        return self._fallback_remediation(vulnerability)
    
    def generate_summary(self, analysis_data: Dict[str, Any]) -> str:
        """Generate executive summary of security analysis."""
        if not self.is_available():
            raise Exception("Ollama is required but not available. Please install and start Ollama with: ollama pull llama3")
        
        prompt = self._create_summary_prompt(analysis_data)
        
        try:
            response = self._generate(prompt)
            if response and len(response.strip()) > 100:
                return response.strip()
            else:
                raise Exception("Ollama generated insufficient response")
        except Exception as e:
            raise Exception(f"AI analysis failed: {e}")
    
    def analyze_vulnerability_pattern(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """AI-powered analysis of vulnerability patterns."""
        if not self.is_available():
            raise Exception("Ollama is required for vulnerability pattern analysis")
        
        prompt = self._create_pattern_analysis_prompt(vulnerabilities)
        
        try:
            response = self._generate(prompt, max_tokens=800)
            if response and len(response.strip()) > 50:
                return response.strip()
            else:
                raise Exception("AI pattern analysis failed")
        except Exception as e:
            raise Exception(f"Vulnerability pattern analysis failed: {e}")
    
    def generate_security_recommendations(self, endpoint_data: Dict[str, Any]) -> str:
        """Generate AI-powered security recommendations."""
        if not self.is_available():
            raise Exception("Ollama is required for security recommendations")
        
        prompt = self._create_recommendations_prompt(endpoint_data)
        
        try:
            response = self._generate(prompt, max_tokens=600)
            if response and len(response.strip()) > 50:
                return response.strip()
            else:
                raise Exception("AI recommendations generation failed")
        except Exception as e:
            raise Exception(f"Security recommendations failed: {e}")
    
    def explain_finding(self, finding: Dict[str, Any]) -> str:
        """Generate explanation for a security finding."""
        if not self.is_available():
            raise Exception("Ollama is required for finding explanations")
        
        prompt = self._create_explanation_prompt(finding)
        
        try:
            response = self._generate(prompt)
            if response and len(response.strip()) > 30:
                return response.strip()
            else:
                raise Exception("AI explanation generation failed")
        except Exception as e:
            raise Exception(f"Finding explanation failed: {e}")
    
    def _generate(self, prompt: str, max_tokens: int = 500) -> Optional[str]:
        """Generate response using Ollama API."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.3,
                "top_p": 0.9
            }
        }
        
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                f"{self.base_url}/api/generate",
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "")
            else:
                raise Exception(f"Ollama API error: {response.status_code}")
    
    def _create_remediation_prompt(self, vulnerability: Dict[str, Any]) -> str:
        """Create prompt for vulnerability remediation."""
        vuln_type = vulnerability.get("test_type", "unknown")
        severity = vulnerability.get("severity", "unknown")
        endpoint = vulnerability.get("endpoint", {})
        evidence = vulnerability.get("evidence", {})
        
        method = endpoint.get("method", "GET")
        path = endpoint.get("path", "/")
        
        prompt = f"""You are a cybersecurity expert. Provide concise remediation advice for this vulnerability:

**Vulnerability Type:** {vuln_type}
**Severity:** {severity}
**Endpoint:** {method} {path}
**Evidence:** {json.dumps(evidence, indent=2)[:500]}

Provide specific, actionable remediation steps in 2-3 sentences. Focus on:
1. Root cause
2. Immediate fix
3. Prevention strategy

Response should be professional and technical but accessible."""
        
        return prompt
    
    def _create_summary_prompt(self, analysis_data: Dict[str, Any]) -> str:
        """Create prompt for executive summary."""
        stats = analysis_data.get("stats", {})
        vulnerabilities = analysis_data.get("vulnerabilities", [])
        
        prompt = f"""You are a cybersecurity analyst. Create an executive summary for this API security assessment:

**Assessment Statistics:**
- Total endpoints analyzed: {stats.get('total_endpoints', 0)}
- Vulnerabilities found: {stats.get('vulnerable_count', 0)}
- High severity: {stats.get('high_severity', 0)}
- Medium severity: {stats.get('medium_severity', 0)}
- Low severity: {stats.get('low_severity', 0)}

**Top Vulnerabilities:**
{json.dumps(vulnerabilities[:3], indent=2)[:800]}

Write a 3-4 sentence executive summary highlighting:
1. Overall security posture
2. Key risks identified
3. Priority recommendations

Keep it business-focused and actionable."""
        
        return prompt
    
    def _create_explanation_prompt(self, finding: Dict[str, Any]) -> str:
        """Create prompt for finding explanation."""
        finding_type = finding.get("type", "unknown")
        severity = finding.get("severity", "unknown")
        message = finding.get("message", "")
        
        prompt = f"""Explain this security finding in simple terms:

**Type:** {finding_type}
**Severity:** {severity}
**Description:** {message}

Provide a 1-2 sentence explanation of:
1. What this means
2. Why it matters

Keep it clear and non-technical."""
        
        return prompt
    
    def _create_pattern_analysis_prompt(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Create prompt for vulnerability pattern analysis."""
        vuln_summary = []
        for vuln in vulnerabilities[:5]:  # Limit to top 5
            vuln_summary.append({
                "type": vuln.get("test_type", "unknown"),
                "severity": vuln.get("severity", "unknown"),
                "endpoint": f"{vuln.get('method', 'GET')} {vuln.get('path', '/')}"
            })
        
        prompt = f"""You are a cybersecurity expert analyzing vulnerability patterns in an API. 

**Vulnerabilities Found:**
{json.dumps(vuln_summary, indent=2)}

Analyze these vulnerabilities and provide insights on:
1. Common attack vectors present
2. Systemic security weaknesses
3. Risk correlation patterns
4. Priority areas for security improvement

Provide a technical analysis in 4-5 sentences focusing on actionable insights."""
        
        return prompt
    
    def _create_recommendations_prompt(self, endpoint_data: Dict[str, Any]) -> str:
        """Create prompt for security recommendations."""
        endpoints = endpoint_data.get("endpoints", [])
        technologies = endpoint_data.get("technologies", [])
        findings = endpoint_data.get("findings", [])
        
        prompt = f"""You are a cybersecurity consultant providing security recommendations for an API.

**API Overview:**
- Total endpoints: {len(endpoints)}
- Technologies: {', '.join(technologies)}
- Security findings: {len(findings)}

**Sample Endpoints:**
{json.dumps(endpoints[:3], indent=2)[:600]}

**Security Findings:**
{json.dumps(findings[:3], indent=2)[:400]}

Provide 4-5 specific security recommendations prioritized by impact:
1. Authentication & Authorization improvements
2. Input validation enhancements  
3. Security configuration hardening
4. Monitoring and detection capabilities

Focus on practical, implementable solutions."""
        
        return prompt
    
    def _fallback_remediation(self, vulnerability: Dict[str, Any]) -> str:
        """Fallback remediation when Ollama is unavailable."""
        vuln_type = vulnerability.get("test_type", "unknown")
        
        remediation_templates = {
            "bola": "Implement proper authorization checks to verify that users can only access resources they own. Use server-side validation of object ownership before returning data.",
            
            "auth_bypass": "Ensure all protected endpoints require valid authentication. Implement consistent authentication middleware across all routes and validate tokens server-side.",
            
            "jwt_manipulation": "Implement proper JWT validation including signature verification, algorithm validation, and claim validation. Never accept unsigned JWTs (alg:none) in production.",
            
            "unknown": "Review the endpoint's security controls and implement appropriate authentication, authorization, and input validation measures."
        }
        
        return remediation_templates.get(vuln_type, remediation_templates["unknown"])
    
    def _fallback_summary(self, analysis_data: Dict[str, Any]) -> str:
        """Fallback summary when Ollama is unavailable."""
        stats = analysis_data.get("stats", {})
        total_endpoints = stats.get("total_endpoints", 0)
        vulnerable_count = stats.get("vulnerable_count", 0)
        high_severity = stats.get("high_severity", 0)
        
        if vulnerable_count == 0:
            return f"Security assessment completed on {total_endpoints} endpoints. No obvious vulnerabilities were detected. Continue monitoring and implementing security best practices."
        
        risk_level = "HIGH" if high_severity > 0 else "MEDIUM" if vulnerable_count > 0 else "LOW"
        
        return f"Security assessment identified {vulnerable_count} potential vulnerabilities across {total_endpoints} endpoints. Risk level: {risk_level}. Immediate attention required for high-severity findings. Implement proper authentication, authorization, and input validation controls."
    
    def _fallback_explanation(self, finding: Dict[str, Any]) -> str:
        """Fallback explanation when Ollama is unavailable."""
        finding_type = finding.get("type", "unknown")
        severity = finding.get("severity", "info")
        
        explanations = {
            "bola": "Users may be able to access data belonging to other users by manipulating ID parameters.",
            "auth_bypass": "Protected endpoints may be accessible without proper authentication credentials.",
            "jwt_manipulation": "JWT tokens may accept invalid signatures or manipulated claims, leading to privilege escalation.",
            "cors_wildcard": "CORS configuration allows requests from any domain, potentially enabling cross-origin attacks.",
            "debug_mode": "Debug mode is enabled, which may expose sensitive information in production.",
            "hardcoded_secret": "Sensitive credentials appear to be hardcoded in the source code."
        }
        
        base_explanation = explanations.get(finding_type, "Security issue detected that requires attention.")
        
        if severity == "high":
            return f"{base_explanation} This is a high-priority security risk."
        elif severity == "medium":
            return f"{base_explanation} This represents a moderate security concern."
        else:
            return f"{base_explanation} This is a low-priority security consideration."
