"""
OpenAPI/Swagger specification discovery and parsing.
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from rich.console import Console

console = Console()

class OpenAPIDiscovery:
    """Discovers and parses OpenAPI specifications."""
    
    def __init__(self, repo_path: Path, verbose: bool = False):
        self.repo_path = repo_path
        self.verbose = verbose
    
    def discover(self, explicit_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Discover OpenAPI specifications in the repository.
        
        Args:
            explicit_path: Explicit path to OpenAPI spec file
            
        Returns:
            Dictionary with discovered specs and parsed endpoints
        """
        results = {
            "specs": [],
            "endpoints": [],
            "errors": []
        }
        
        spec_files = []
        
        # Use explicit path if provided
        if explicit_path:
            explicit_file = Path(explicit_path)
            if explicit_file.is_absolute():
                spec_files.append(explicit_file)
            else:
                spec_files.append(self.repo_path / explicit_path)
        else:
            # Search for common OpenAPI file patterns
            patterns = [
                "openapi.yaml", "openapi.yml", "openapi.json",
                "swagger.yaml", "swagger.yml", "swagger.json",
                "api.yaml", "api.yml", "api.json",
                "**/openapi.yaml", "**/openapi.yml", "**/openapi.json",
                "**/swagger.yaml", "**/swagger.yml", "**/swagger.json",
                "docs/openapi.*", "docs/swagger.*",
                "spec/openapi.*", "spec/swagger.*"
            ]
            
            for pattern in patterns:
                spec_files.extend(self.repo_path.glob(pattern))
        
        # Remove duplicates and non-existent files
        spec_files = list(set(f for f in spec_files if f.exists() and f.is_file()))
        
        for spec_file in spec_files:
            try:
                spec_data = self._parse_spec_file(spec_file)
                if spec_data:
                    endpoints = self._extract_endpoints(spec_data, spec_file)
                    
                    results["specs"].append({
                        "file": str(spec_file),
                        "version": spec_data.get("openapi", spec_data.get("swagger", "unknown")),
                        "title": spec_data.get("info", {}).get("title", "Unknown API"),
                        "endpoints_count": len(endpoints)
                    })
                    
                    results["endpoints"].extend(endpoints)
                    
                    if self.verbose:
                        console.print(f"   📄 Parsed {spec_file.name}: {len(endpoints)} endpoints")
                        
            except Exception as e:
                error_msg = f"Failed to parse {spec_file}: {e}"
                results["errors"].append(error_msg)
                if self.verbose:
                    console.print(f"   ❌ {error_msg}", style="red")
        
        return results
    
    def _parse_spec_file(self, spec_file: Path) -> Optional[Dict[str, Any]]:
        """Parse OpenAPI spec file (JSON or YAML)."""
        try:
            with open(spec_file, 'r', encoding='utf-8') as f:
                if spec_file.suffix.lower() == '.json':
                    return json.load(f)
                else:
                    return yaml.safe_load(f)
        except Exception as e:
            if self.verbose:
                console.print(f"   ⚠️  Could not parse {spec_file}: {e}", style="yellow")
            return None
    
    def _extract_endpoints(self, spec_data: Dict[str, Any], spec_file: Path) -> List[Dict[str, Any]]:
        """Extract endpoints from OpenAPI specification."""
        endpoints = []
        
        # Get base information
        servers = spec_data.get("servers", [])
        base_path = spec_data.get("basePath", "")
        
        # Extract paths
        paths = spec_data.get("paths", {})
        
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            
            # Handle path-level parameters
            path_params = path_item.get("parameters", [])
            
            # Process each HTTP method
            for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
                if method not in path_item:
                    continue
                
                operation = path_item[method]
                if not isinstance(operation, dict):
                    continue
                
                # Extract endpoint information
                endpoint = {
                    "method": method.upper(),
                    "path": path,
                    "source": "openapi",
                    "source_file": str(spec_file),
                    "operation_id": operation.get("operationId"),
                    "summary": operation.get("summary", ""),
                    "description": operation.get("description", ""),
                    "tags": operation.get("tags", []),
                    "parameters": [],
                    "auth_requirements": [],
                    "responses": {},
                    "security_hints": []
                }
                
                # Extract parameters
                all_params = path_params + operation.get("parameters", [])
                for param in all_params:
                    if isinstance(param, dict):
                        param_info = {
                            "name": param.get("name", ""),
                            "in": param.get("in", ""),
                            "required": param.get("required", False),
                            "type": self._get_param_type(param),
                            "description": param.get("description", "")
                        }
                        endpoint["parameters"].append(param_info)
                
                # Extract request body (OpenAPI 3.x)
                request_body = operation.get("requestBody")
                if request_body:
                    content = request_body.get("content", {})
                    for media_type, media_info in content.items():
                        endpoint["parameters"].append({
                            "name": "body",
                            "in": "body",
                            "required": request_body.get("required", False),
                            "type": media_type,
                            "description": request_body.get("description", "")
                        })
                
                # Extract security requirements
                security = operation.get("security", spec_data.get("security", []))
                for sec_req in security:
                    if isinstance(sec_req, dict):
                        endpoint["auth_requirements"].extend(sec_req.keys())
                
                # Extract responses
                responses = operation.get("responses", {})
                for status_code, response in responses.items():
                    if isinstance(response, dict):
                        endpoint["responses"][status_code] = {
                            "description": response.get("description", ""),
                            "content_types": list(response.get("content", {}).keys())
                        }
                
                # Security analysis hints
                endpoint["security_hints"] = self._analyze_endpoint_security(endpoint, operation)
                
                endpoints.append(endpoint)
        
        return endpoints
    
    def _get_param_type(self, param: Dict[str, Any]) -> str:
        """Extract parameter type from OpenAPI parameter definition."""
        # OpenAPI 3.x schema
        schema = param.get("schema", {})
        if schema:
            return schema.get("type", "string")
        
        # OpenAPI 2.x (Swagger) direct type
        return param.get("type", "string")
    
    def _analyze_endpoint_security(self, endpoint: Dict[str, Any], operation: Dict[str, Any]) -> List[str]:
        """Analyze endpoint for security patterns and hints."""
        hints = []
        
        path = endpoint["path"].lower()
        method = endpoint["method"]
        
        # Check for ID-like parameters (potential BOLA targets)
        for param in endpoint["parameters"]:
            param_name = param["name"].lower()
            if any(id_hint in param_name for id_hint in ["id", "uuid", "key"]):
                hints.append("has_id_param")
        
        # Check for path parameters that look like IDs
        if "{" in path and "}" in path:
            import re
            path_params = re.findall(r'\{([^}]+)\}', path)
            for param in path_params:
                if any(id_hint in param.lower() for id_hint in ["id", "uuid", "key"]):
                    hints.append("has_path_id")
        
        # Check for authentication requirements
        if not endpoint["auth_requirements"]:
            hints.append("no_auth_required")
        
        # Check for mutating operations
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            hints.append("mutating_operation")
        
        # Check for admin/sensitive paths
        sensitive_patterns = ["admin", "internal", "debug", "test", "config", "settings"]
        if any(pattern in path for pattern in sensitive_patterns):
            hints.append("sensitive_path")
        
        return hints
