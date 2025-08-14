"""
Node.js framework discovery (Express, NestJS, etc.).
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any
from rich.console import Console

console = Console()

class NodeDiscovery:
    """Discovers Node.js API endpoints from various frameworks."""
    
    def __init__(self, repo_path: Path, verbose: bool = False):
        self.repo_path = repo_path
        self.verbose = verbose
    
    def discover(self) -> Dict[str, Any]:
        """
        Discover Node.js endpoints from framework patterns.
        
        Returns:
            Dictionary with discovered endpoints and security findings
        """
        results = {
            "endpoints": [],
            "security_findings": [],
            "technologies": [],
            "package_info": {}
        }
        
        # Analyze package.json for framework detection
        package_json = self.repo_path / "package.json"
        if package_json.exists():
            results["package_info"] = self._analyze_package_json(package_json)
            results["technologies"].extend(results["package_info"].get("frameworks", []))
        
        # Find JavaScript/TypeScript files
        js_files = []
        for pattern in ["**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"]:
            js_files.extend(self.repo_path.glob(pattern))
        
        # Filter out node_modules and other irrelevant directories
        js_files = [f for f in js_files if "node_modules" not in str(f) and ".git" not in str(f)]
        
        for js_file in js_files:
            try:
                file_content = self._read_file(js_file)
                if file_content:
                    # Discover endpoints from different frameworks
                    endpoints = []
                    endpoints.extend(self._discover_express_routes(file_content, js_file))
                    endpoints.extend(self._discover_nestjs_routes(file_content, js_file))
                    endpoints.extend(self._discover_fastify_routes(file_content, js_file))
                    
                    results["endpoints"].extend(endpoints)
                    
                    # Security analysis
                    security_findings = self._analyze_security_patterns(file_content, js_file)
                    results["security_findings"].extend(security_findings)
                    
            except Exception as e:
                if self.verbose:
                    console.print(f"   ⚠️  Could not analyze {js_file}: {e}", style="yellow")
        
        return results
    
    def _analyze_package_json(self, package_json: Path) -> Dict[str, Any]:
        """Analyze package.json for framework information."""
        try:
            with open(package_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            dependencies = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            
            frameworks = []
            if "express" in dependencies:
                frameworks.append("express")
            if "@nestjs/core" in dependencies:
                frameworks.append("nestjs")
            if "fastify" in dependencies:
                frameworks.append("fastify")
            if "koa" in dependencies:
                frameworks.append("koa")
            if "hapi" in dependencies:
                frameworks.append("hapi")
            
            return {
                "name": data.get("name", ""),
                "version": data.get("version", ""),
                "frameworks": frameworks,
                "dependencies": list(dependencies.keys())
            }
            
        except Exception as e:
            if self.verbose:
                console.print(f"   ⚠️  Could not parse package.json: {e}", style="yellow")
            return {}
    
    def _read_file(self, file_path: Path) -> str:
        """Read file content safely."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            return ""
    
    def _discover_express_routes(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Discover Express.js routes."""
        endpoints = []
        
        # Express route patterns
        patterns = [
            # app.method(path, handler)
            r'(?:app|router)\.(?P<method>get|post|put|patch|delete|head|options|all)\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`]',
            # router.route(path).method(handler)
            r'(?:app|router)\.route\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`]\s*\)\.(?P<method>get|post|put|patch|delete|head|options|all)',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                method = match.group('method').upper()
                path = match.group('path')
                
                endpoint = {
                    "method": method,
                    "path": path,
                    "source": "express",
                    "source_file": str(file_path),
                    "parameters": self._extract_path_params(path),
                    "auth_requirements": [],
                    "security_hints": self._analyze_endpoint_patterns(method, path, content)
                }
                
                endpoints.append(endpoint)
        
        return endpoints
    
    def _discover_nestjs_routes(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Discover NestJS routes."""
        endpoints = []
        
        # NestJS decorator patterns
        controller_match = re.search(r'@Controller\s*\(\s*[\'"`]([^\'"`]*)[\'"`]\s*\)', content)
        base_path = controller_match.group(1) if controller_match else ""
        
        # Method decorators
        method_patterns = [
            r'@(?P<method>Get|Post|Put|Patch|Delete|Head|Options|All)\s*\(\s*[\'"`](?P<path>[^\'"`]*)[\'"`]\s*\)',
            r'@(?P<method>Get|Post|Put|Patch|Delete|Head|Options|All)\s*\(\s*\)'  # No path specified
        ]
        
        for pattern in method_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                method = match.group('method').upper()
                path = match.group('path') if 'path' in match.groupdict() and match.group('path') else ""
                
                # Combine base path and method path
                full_path = f"/{base_path.strip('/')}/{path.strip('/')}" if base_path else f"/{path.strip('/')}"
                full_path = full_path.rstrip('/') or '/'
                
                endpoint = {
                    "method": method,
                    "path": full_path,
                    "source": "nestjs",
                    "source_file": str(file_path),
                    "parameters": self._extract_path_params(full_path),
                    "auth_requirements": self._extract_nestjs_guards(content),
                    "security_hints": self._analyze_endpoint_patterns(method, full_path, content)
                }
                
                endpoints.append(endpoint)
        
        return endpoints
    
    def _discover_fastify_routes(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Discover Fastify routes."""
        endpoints = []
        
        # Fastify route patterns
        patterns = [
            r'(?:fastify|app)\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`]',
            r'(?:fastify|app)\.route\s*\(\s*\{\s*method:\s*[\'"`](?P<method>[^\'"`]+)[\'"`]\s*,\s*url:\s*[\'"`](?P<path>[^\'"`]+)[\'"`]'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                method = match.group('method').upper()
                path = match.group('path')
                
                endpoint = {
                    "method": method,
                    "path": path,
                    "source": "fastify",
                    "source_file": str(file_path),
                    "parameters": self._extract_path_params(path),
                    "auth_requirements": [],
                    "security_hints": self._analyze_endpoint_patterns(method, path, content)
                }
                
                endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_path_params(self, path: str) -> List[Dict[str, Any]]:
        """Extract path parameters from route path."""
        params = []
        
        # Express-style parameters (:param)
        express_params = re.findall(r':(\w+)', path)
        for param in express_params:
            params.append({
                "name": param,
                "in": "path",
                "required": True,
                "type": "string"
            })
        
        # Fastify-style parameters (:param)
        fastify_params = re.findall(r':(\w+)', path)
        for param in fastify_params:
            if param not in [p["name"] for p in params]:
                params.append({
                    "name": param,
                    "in": "path",
                    "required": True,
                    "type": "string"
                })
        
        return params
    
    def _extract_nestjs_guards(self, content: str) -> List[str]:
        """Extract NestJS guards (auth requirements)."""
        guards = []
        
        guard_patterns = [
            r'@UseGuards\s*\(\s*(\w+)',
            r'@AuthGuard\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'
        ]
        
        for pattern in guard_patterns:
            matches = re.findall(pattern, content)
            guards.extend(matches)
        
        return guards
    
    def _analyze_endpoint_patterns(self, method: str, path: str, content: str) -> List[str]:
        """Analyze endpoint for security patterns."""
        hints = []
        
        path_lower = path.lower()
        
        # Check for ID-like parameters
        if re.search(r':(?:id|uuid|key|\w*id)', path):
            hints.append("has_path_id")
        
        # Check for mutating operations
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            hints.append("mutating_operation")
        
        # Check for sensitive paths
        sensitive_patterns = ["admin", "internal", "debug", "test", "config", "settings"]
        if any(pattern in path_lower for pattern in sensitive_patterns):
            hints.append("sensitive_path")
        
        # Check for authentication middleware
        if re.search(r'auth|authenticate|requireAuth|isAuthenticated', content, re.IGNORECASE):
            hints.append("has_auth_middleware")
        else:
            hints.append("no_auth_detected")
        
        return hints
    
    def _analyze_security_patterns(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze file for security anti-patterns."""
        findings = []
        
        # CORS misconfigurations
        if re.search(r'cors.*origin.*\*', content, re.IGNORECASE):
            findings.append({
                "type": "cors_wildcard",
                "severity": "medium",
                "message": "Wildcard CORS origin detected",
                "file": str(file_path),
                "pattern": "cors origin: *"
            })
        
        # Debug mode enabled
        if re.search(r'debug.*true|NODE_ENV.*development', content, re.IGNORECASE):
            findings.append({
                "type": "debug_mode",
                "severity": "low",
                "message": "Debug mode may be enabled",
                "file": str(file_path),
                "pattern": "debug: true or NODE_ENV: development"
            })
        
        # Hardcoded secrets
        secret_patterns = [
            r'(?:password|secret|key|token)\s*[:=]\s*[\'"`][^\'"`]{8,}[\'"`]',
            r'(?:api_key|apikey|access_token)\s*[:=]\s*[\'"`][^\'"`]{8,}[\'"`]'
        ]
        
        for pattern in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({
                    "type": "hardcoded_secret",
                    "severity": "high",
                    "message": "Potential hardcoded secret detected",
                    "file": str(file_path),
                    "pattern": "hardcoded credentials"
                })
        
        return findings
