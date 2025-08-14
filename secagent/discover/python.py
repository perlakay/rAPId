"""
Python framework discovery (FastAPI, Flask, Django, DRF).
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from rich.console import Console

console = Console()

class PythonDiscovery:
    """Discovers Python API endpoints from various frameworks."""
    
    def __init__(self, repo_path: Path, verbose: bool = False):
        self.repo_path = repo_path
        self.verbose = verbose
    
    def discover(self) -> Dict[str, Any]:
        """
        Discover Python endpoints from framework patterns.
        
        Returns:
            Dictionary with discovered endpoints and security findings
        """
        results = {
            "endpoints": [],
            "security_findings": [],
            "technologies": [],
            "requirements": {}
        }
        
        # Analyze requirements for framework detection
        requirements_files = ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"]
        for req_file in requirements_files:
            req_path = self.repo_path / req_file
            if req_path.exists():
                results["requirements"][req_file] = self._analyze_requirements(req_path)
                results["technologies"].extend(results["requirements"][req_file].get("frameworks", []))
        
        # Find Python files
        py_files = list(self.repo_path.glob("**/*.py"))
        py_files = [f for f in py_files if "__pycache__" not in str(f) and ".git" not in str(f)]
        
        for py_file in py_files:
            try:
                file_content = self._read_file(py_file)
                if file_content:
                    # Discover endpoints from different frameworks
                    endpoints = []
                    endpoints.extend(self._discover_fastapi_routes(file_content, py_file))
                    endpoints.extend(self._discover_flask_routes(file_content, py_file))
                    endpoints.extend(self._discover_django_routes(file_content, py_file))
                    endpoints.extend(self._discover_drf_routes(file_content, py_file))
                    
                    results["endpoints"].extend(endpoints)
                    
                    # Security analysis
                    security_findings = self._analyze_security_patterns(file_content, py_file)
                    results["security_findings"].extend(security_findings)
                    
            except Exception as e:
                if self.verbose:
                    console.print(f"   ⚠️  Could not analyze {py_file}: {e}", style="yellow")
        
        return results
    
    def _analyze_requirements(self, req_file: Path) -> Dict[str, Any]:
        """Analyze requirements file for framework information."""
        try:
            content = self._read_file(req_file)
            frameworks = []
            dependencies = []
            
            if req_file.name == "requirements.txt":
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        dep = line.split('==')[0].split('>=')[0].split('<=')[0].strip()
                        dependencies.append(dep)
                        
                        if dep.lower() in ["fastapi", "uvicorn"]:
                            frameworks.append("fastapi")
                        elif dep.lower() in ["flask"]:
                            frameworks.append("flask")
                        elif dep.lower() in ["django"]:
                            frameworks.append("django")
                        elif dep.lower() in ["djangorestframework", "drf"]:
                            frameworks.append("drf")
            
            elif req_file.name == "pyproject.toml":
                # Basic TOML parsing for dependencies
                if "fastapi" in content.lower():
                    frameworks.append("fastapi")
                if "flask" in content.lower():
                    frameworks.append("flask")
                if "django" in content.lower():
                    frameworks.append("django")
            
            return {
                "frameworks": list(set(frameworks)),
                "dependencies": dependencies
            }
            
        except Exception as e:
            if self.verbose:
                console.print(f"   ⚠️  Could not parse {req_file}: {e}", style="yellow")
            return {}
    
    def _read_file(self, file_path: Path) -> str:
        """Read file content safely."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            return ""
    
    def _discover_fastapi_routes(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Discover FastAPI routes."""
        endpoints = []
        
        # FastAPI route patterns
        patterns = [
            r'@app\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`]',
            r'@router\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`]',
            r'app\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`]',
            r'router\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`]'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                method = match.group('method').upper()
                path = match.group('path')
                
                endpoint = {
                    "method": method,
                    "path": path,
                    "source": "fastapi",
                    "source_file": str(file_path),
                    "parameters": self._extract_fastapi_params(path, content),
                    "auth_requirements": self._extract_fastapi_dependencies(content),
                    "security_hints": self._analyze_endpoint_patterns(method, path, content)
                }
                
                endpoints.append(endpoint)
        
        return endpoints
    
    def _discover_flask_routes(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Discover Flask routes."""
        endpoints = []
        
        # Flask route patterns
        patterns = [
            r'@app\.route\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`](?:.*methods\s*=\s*\[([^\]]+)\])?',
            r'@bp\.route\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`](?:.*methods\s*=\s*\[([^\]]+)\])?',
            r'@blueprint\.route\s*\(\s*[\'"`](?P<path>[^\'"`]+)[\'"`](?:.*methods\s*=\s*\[([^\]]+)\])?'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                path = match.group('path')
                methods_str = match.group(2) if len(match.groups()) > 1 and match.group(2) else "GET"
                
                # Parse methods
                methods = []
                if methods_str:
                    methods = [m.strip().strip('\'"').upper() for m in methods_str.split(',')]
                else:
                    methods = ["GET"]
                
                for method in methods:
                    endpoint = {
                        "method": method,
                        "path": path,
                        "source": "flask",
                        "source_file": str(file_path),
                        "parameters": self._extract_flask_params(path),
                        "auth_requirements": self._extract_flask_decorators(content),
                        "security_hints": self._analyze_endpoint_patterns(method, path, content)
                    }
                    
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _discover_django_routes(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Discover Django URL patterns."""
        endpoints = []
        
        # Django URL patterns
        if "urlpatterns" in content:
            # Basic pattern matching for Django URLs
            url_patterns = [
                r'path\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*,\s*(\w+)',
                r'url\s*\(\s*r?[\'"`]([^\'"`]+)[\'"`]\s*,\s*(\w+)',
                r're_path\s*\(\s*r?[\'"`]([^\'"`]+)[\'"`]\s*,\s*(\w+)'
            ]
            
            for pattern in url_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    path = match.group(1)
                    view_name = match.group(2)
                    
                    # Django URLs typically handle multiple methods
                    endpoint = {
                        "method": "GET",  # Default, actual methods depend on view
                        "path": path,
                        "source": "django",
                        "source_file": str(file_path),
                        "view_name": view_name,
                        "parameters": self._extract_django_params(path),
                        "auth_requirements": [],
                        "security_hints": self._analyze_endpoint_patterns("GET", path, content)
                    }
                    
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _discover_drf_routes(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Discover Django REST Framework routes."""
        endpoints = []
        
        # DRF ViewSet patterns
        if "ViewSet" in content or "APIView" in content:
            # Look for class-based views
            class_pattern = r'class\s+(\w+)\s*\([^)]*(?:ViewSet|APIView)[^)]*\)'
            class_matches = re.finditer(class_pattern, content)
            
            for class_match in class_matches:
                class_name = class_match.group(1)
                
                # Look for method definitions in the class
                method_patterns = [
                    r'def\s+(get|post|put|patch|delete|head|options)\s*\(',
                    r'def\s+(list|create|retrieve|update|partial_update|destroy)\s*\('
                ]
                
                for method_pattern in method_patterns:
                    method_matches = re.finditer(method_pattern, content)
                    for method_match in method_matches:
                        method_name = method_match.group(1)
                        
                        # Map DRF method names to HTTP methods
                        http_method = self._map_drf_method(method_name)
                        
                        endpoint = {
                            "method": http_method,
                            "path": f"/{class_name.lower()}/",  # Approximate path
                            "source": "drf",
                            "source_file": str(file_path),
                            "view_class": class_name,
                            "view_method": method_name,
                            "parameters": [],
                            "auth_requirements": self._extract_drf_permissions(content),
                            "security_hints": self._analyze_endpoint_patterns(http_method, f"/{class_name.lower()}/", content)
                        }
                        
                        endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_fastapi_params(self, path: str, content: str) -> List[Dict[str, Any]]:
        """Extract FastAPI path and query parameters."""
        params = []
        
        # Path parameters {param}
        path_params = re.findall(r'\{(\w+)\}', path)
        for param in path_params:
            params.append({
                "name": param,
                "in": "path",
                "required": True,
                "type": "string"
            })
        
        return params
    
    def _extract_flask_params(self, path: str) -> List[Dict[str, Any]]:
        """Extract Flask route parameters."""
        params = []
        
        # Flask parameters <param> or <int:param>
        flask_params = re.findall(r'<(?:(\w+):)?(\w+)>', path)
        for type_hint, param_name in flask_params:
            params.append({
                "name": param_name,
                "in": "path",
                "required": True,
                "type": type_hint or "string"
            })
        
        return params
    
    def _extract_django_params(self, path: str) -> List[Dict[str, Any]]:
        """Extract Django URL parameters."""
        params = []
        
        # Django regex groups (?P<name>pattern)
        django_params = re.findall(r'\(\?P<(\w+)>[^)]+\)', path)
        for param in django_params:
            params.append({
                "name": param,
                "in": "path",
                "required": True,
                "type": "string"
            })
        
        return params
    
    def _extract_fastapi_dependencies(self, content: str) -> List[str]:
        """Extract FastAPI dependencies (auth requirements)."""
        dependencies = []
        
        dep_patterns = [
            r'Depends\s*\(\s*(\w+)',
            r'Security\s*\(\s*(\w+)'
        ]
        
        for pattern in dep_patterns:
            matches = re.findall(pattern, content)
            dependencies.extend(matches)
        
        return dependencies
    
    def _extract_flask_decorators(self, content: str) -> List[str]:
        """Extract Flask authentication decorators."""
        decorators = []
        
        decorator_patterns = [
            r'@login_required',
            r'@auth\.login_required',
            r'@require_auth',
            r'@jwt_required'
        ]
        
        for pattern in decorator_patterns:
            if re.search(pattern, content):
                decorators.append(pattern.strip('@'))
        
        return decorators
    
    def _extract_drf_permissions(self, content: str) -> List[str]:
        """Extract DRF permission classes."""
        permissions = []
        
        permission_patterns = [
            r'permission_classes\s*=\s*\[([^\]]+)\]',
            r'IsAuthenticated',
            r'IsAdminUser',
            r'AllowAny'
        ]
        
        for pattern in permission_patterns:
            matches = re.findall(pattern, content)
            permissions.extend(matches)
        
        return permissions
    
    def _map_drf_method(self, method_name: str) -> str:
        """Map DRF method names to HTTP methods."""
        mapping = {
            "list": "GET",
            "create": "POST",
            "retrieve": "GET",
            "update": "PUT",
            "partial_update": "PATCH",
            "destroy": "DELETE",
            "get": "GET",
            "post": "POST",
            "put": "PUT",
            "patch": "PATCH",
            "delete": "DELETE",
            "head": "HEAD",
            "options": "OPTIONS"
        }
        return mapping.get(method_name.lower(), "GET")
    
    def _analyze_endpoint_patterns(self, method: str, path: str, content: str) -> List[str]:
        """Analyze endpoint for security patterns."""
        hints = []
        
        path_lower = path.lower()
        
        # Check for ID-like parameters
        if re.search(r'[{<](?:\w+:)?(?:id|uuid|key|\w*id)[}>]', path):
            hints.append("has_path_id")
        
        # Check for mutating operations
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            hints.append("mutating_operation")
        
        # Check for sensitive paths
        sensitive_patterns = ["admin", "internal", "debug", "test", "config", "settings"]
        if any(pattern in path_lower for pattern in sensitive_patterns):
            hints.append("sensitive_path")
        
        # Check for authentication decorators/dependencies
        auth_patterns = [
            r'@login_required', r'@auth', r'@jwt_required',
            r'Depends\s*\(', r'Security\s*\(',
            r'permission_classes', r'IsAuthenticated'
        ]
        
        has_auth = any(re.search(pattern, content, re.IGNORECASE) for pattern in auth_patterns)
        if has_auth:
            hints.append("has_auth_middleware")
        else:
            hints.append("no_auth_detected")
        
        return hints
    
    def _analyze_security_patterns(self, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze file for security anti-patterns."""
        findings = []
        
        # Debug mode enabled
        if re.search(r'DEBUG\s*=\s*True', content):
            findings.append({
                "type": "debug_mode",
                "severity": "medium",
                "message": "Debug mode enabled",
                "file": str(file_path),
                "pattern": "DEBUG = True"
            })
        
        # Hardcoded secrets
        secret_patterns = [
            r'(?:SECRET_KEY|PASSWORD|API_KEY|TOKEN)\s*=\s*[\'"`][^\'"`]{8,}[\'"`]',
            r'(?:password|secret|key|token)\s*=\s*[\'"`][^\'"`]{8,}[\'"`]'
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
        
        # Insecure CORS settings
        if re.search(r'CORS_ALLOW_ALL_ORIGINS\s*=\s*True', content):
            findings.append({
                "type": "cors_wildcard",
                "severity": "medium",
                "message": "CORS allows all origins",
                "file": str(file_path),
                "pattern": "CORS_ALLOW_ALL_ORIGINS = True"
            })
        
        return findings
