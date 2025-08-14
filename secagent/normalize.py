"""
Endpoint normalization and parameter detection.
"""

import re
import uuid
from typing import Dict, List, Any
from rich.console import Console

console = Console()

class EndpointNormalizer:
    """Normalizes discovered endpoints and detects security-relevant parameters."""
    
    def __init__(self):
        self.id_patterns = [
            r'\b(?:id|uuid|key|pk|_id)\b',
            r'\b\d+\b',  # Numeric IDs
            r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',  # UUIDs
            r'\b[0-9a-f]{24}\b',  # MongoDB ObjectIds
            r'\b[A-Za-z0-9_-]{20,}\b'  # Long alphanumeric strings
        ]
    
    def normalize(self, static_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalize discovered endpoints from static analysis.
        
        Args:
            static_results: Results from static discovery
            
        Returns:
            List of normalized endpoint dictionaries
        """
        normalized_endpoints = []
        
        for endpoint in static_results.get("endpoints", []):
            normalized = self._normalize_endpoint(endpoint)
            if normalized:
                normalized_endpoints.append(normalized)
        
        # Remove duplicates based on method + path template
        unique_endpoints = self._deduplicate_endpoints(normalized_endpoints)
        
        return unique_endpoints
    
    def _normalize_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a single endpoint."""
        try:
            # Extract basic information
            method = endpoint.get("method", "GET").upper()
            path = endpoint.get("path", "/")
            source = endpoint.get("source", "unknown")
            
            # Create path template (replace dynamic segments with placeholders)
            path_template = self._create_path_template(path)
            
            # Extract and classify parameters
            parameters = self._extract_all_parameters(endpoint, path)
            
            # Detect ID-like parameters for BOLA testing
            id_params = self._detect_id_parameters(parameters, path)
            
            # Analyze authentication requirements
            auth_info = self._analyze_auth_requirements(endpoint)
            
            # Generate security hints
            security_hints = self._generate_security_hints(endpoint, parameters, id_params)
            
            normalized = {
                "id": str(uuid.uuid4()),
                "method": method,
                "path": path,
                "path_template": path_template,
                "source": source,
                "source_file": endpoint.get("source_file", ""),
                "parameters": parameters,
                "id_parameters": id_params,
                "auth_requirements": auth_info["requirements"],
                "auth_detected": auth_info["detected"],
                "security_hints": security_hints,
                "metadata": {
                    "operation_id": endpoint.get("operation_id"),
                    "summary": endpoint.get("summary", ""),
                    "description": endpoint.get("description", ""),
                    "tags": endpoint.get("tags", []),
                    "responses": endpoint.get("responses", {}),
                    "view_name": endpoint.get("view_name"),
                    "view_class": endpoint.get("view_class"),
                    "operation_type": endpoint.get("operation_type"),
                    "operation_name": endpoint.get("operation_name")
                }
            }
            
            return normalized
            
        except Exception as e:
            console.print(f"   ⚠️  Failed to normalize endpoint {endpoint}: {e}", style="yellow")
            return None
    
    def _create_path_template(self, path: str) -> str:
        """Create a path template by replacing dynamic segments."""
        template = path
        
        # Replace various parameter formats with {param}
        replacements = [
            (r'\{(\w+)\}', r'{\1}'),  # FastAPI/OpenAPI: {id}
            (r'<(?:\w+:)?(\w+)>', r'{\1}'),  # Flask: <id> or <int:id>
            (r':(\w+)', r'{\1}'),  # Express: :id
            (r'\(\?P<(\w+)>[^)]+\)', r'{\1}'),  # Django: (?P<id>\d+)
        ]
        
        for pattern, replacement in replacements:
            template = re.sub(pattern, replacement, template)
        
        # Replace numeric segments that look like IDs
        template = re.sub(r'/\d+(?=/|$)', '/{id}', template)
        
        # Replace UUID-like segments
        template = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)', '/{uuid}', template)
        
        return template
    
    def _extract_all_parameters(self, endpoint: Dict[str, Any], path: str) -> List[Dict[str, Any]]:
        """Extract all parameters from endpoint definition."""
        parameters = []
        
        # Add existing parameters from discovery
        existing_params = endpoint.get("parameters", [])
        if isinstance(existing_params, list):
            parameters.extend(existing_params)
        
        # Extract path parameters if not already captured
        path_params = self._extract_path_parameters(path)
        for param in path_params:
            if not any(p.get("name") == param["name"] and p.get("in") == "path" for p in parameters):
                parameters.append(param)
        
        # Add common query parameters based on endpoint patterns
        query_params = self._infer_query_parameters(endpoint)
        parameters.extend(query_params)
        
        return parameters
    
    def _extract_path_parameters(self, path: str) -> List[Dict[str, Any]]:
        """Extract path parameters from URL path."""
        parameters = []
        
        # Various path parameter formats
        param_patterns = [
            (r'\{(\w+)\}', 'string'),  # {id}
            (r'<(?:(\w+):)?(\w+)>', 'string'),  # <id> or <int:id>
            (r':(\w+)', 'string'),  # :id
            (r'\(\?P<(\w+)>[^)]+\)', 'string'),  # (?P<id>\d+)
        ]
        
        for pattern, default_type in param_patterns:
            matches = re.finditer(pattern, path)
            for match in matches:
                if len(match.groups()) == 2:  # Flask-style with type
                    param_type = match.group(1) or default_type
                    param_name = match.group(2)
                else:
                    param_type = default_type
                    param_name = match.group(1)
                
                parameters.append({
                    "name": param_name,
                    "in": "path",
                    "required": True,
                    "type": param_type,
                    "description": f"Path parameter: {param_name}"
                })
        
        return parameters
    
    def _infer_query_parameters(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Infer common query parameters based on endpoint patterns."""
        parameters = []
        
        method = endpoint.get("method", "GET")
        path = endpoint.get("path", "").lower()
        
        # Common pagination parameters for GET endpoints
        if method == "GET":
            if any(keyword in path for keyword in ["list", "search", "users", "items", "posts"]):
                parameters.extend([
                    {
                        "name": "page",
                        "in": "query",
                        "required": False,
                        "type": "integer",
                        "description": "Page number for pagination"
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "required": False,
                        "type": "integer",
                        "description": "Number of items per page"
                    },
                    {
                        "name": "offset",
                        "in": "query",
                        "required": False,
                        "type": "integer",
                        "description": "Offset for pagination"
                    }
                ])
        
        # Search parameters
        if "search" in path:
            parameters.append({
                "name": "q",
                "in": "query",
                "required": False,
                "type": "string",
                "description": "Search query"
            })
        
        return parameters
    
    def _detect_id_parameters(self, parameters: List[Dict[str, Any]], path: str) -> List[Dict[str, Any]]:
        """Detect ID-like parameters that could be targets for BOLA attacks."""
        id_params = []
        
        for param in parameters:
            param_name = param.get("name", "").lower()
            param_type = param.get("type", "")
            
            # Check if parameter name suggests it's an ID
            is_id_name = any(re.search(pattern, param_name, re.IGNORECASE) for pattern in self.id_patterns[:1])  # Just the name patterns
            
            # Check if parameter type suggests it's an ID
            is_id_type = param_type in ["integer", "string"] and param.get("in") in ["path", "query"]
            
            # Additional context from path
            path_suggests_id = any(segment in path.lower() for segment in ["/{id}", "/{uuid}", "/users/", "/items/"])
            
            if is_id_name or (is_id_type and path_suggests_id):
                id_param = param.copy()
                id_param["id_confidence"] = self._calculate_id_confidence(param, path)
                id_param["bola_testable"] = param.get("in") in ["path", "query"]
                id_params.append(id_param)
        
        return id_params
    
    def _calculate_id_confidence(self, param: Dict[str, Any], path: str) -> float:
        """Calculate confidence that a parameter is an ID (0.0 to 1.0)."""
        confidence = 0.0
        
        param_name = param.get("name", "").lower()
        
        # High confidence indicators
        if param_name in ["id", "uuid", "key", "pk"]:
            confidence += 0.8
        elif param_name.endswith("_id") or param_name.endswith("id"):
            confidence += 0.6
        elif "id" in param_name:
            confidence += 0.4
        
        # Type indicators
        if param.get("type") == "integer" and param.get("in") == "path":
            confidence += 0.3
        elif param.get("type") == "string" and param.get("in") == "path":
            confidence += 0.2
        
        # Path context
        if "/{id}" in path or "/{uuid}" in path:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _analyze_auth_requirements(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze authentication requirements for the endpoint."""
        auth_requirements = endpoint.get("auth_requirements", [])
        security_hints = endpoint.get("security_hints", [])
        
        # Determine if authentication is detected
        auth_detected = bool(auth_requirements) or "has_auth_middleware" in security_hints
        
        # Classify authentication types
        auth_types = []
        for req in auth_requirements:
            req_lower = str(req).lower()
            if "bearer" in req_lower or "jwt" in req_lower:
                auth_types.append("jwt")
            elif "basic" in req_lower:
                auth_types.append("basic")
            elif "api" in req_lower or "key" in req_lower:
                auth_types.append("api_key")
            elif "oauth" in req_lower:
                auth_types.append("oauth")
            else:
                auth_types.append("unknown")
        
        return {
            "requirements": auth_requirements,
            "detected": auth_detected,
            "types": list(set(auth_types)),
            "confidence": 0.8 if auth_detected else 0.2
        }
    
    def _generate_security_hints(self, endpoint: Dict[str, Any], parameters: List[Dict[str, Any]], id_params: List[Dict[str, Any]]) -> List[str]:
        """Generate security testing hints for the endpoint."""
        hints = []
        
        # Copy existing hints
        existing_hints = endpoint.get("security_hints", [])
        if isinstance(existing_hints, list):
            hints.extend(existing_hints)
        
        method = endpoint.get("method", "GET")
        path = endpoint.get("path", "").lower()
        
        # BOLA testing hints
        if id_params:
            hints.append("bola_testable")
            if any(p.get("bola_testable", False) for p in id_params):
                hints.append("high_bola_risk")
        
        # Authentication testing hints
        auth_detected = "has_auth_middleware" in hints or endpoint.get("auth_requirements")
        if not auth_detected:
            hints.append("auth_bypass_testable")
        
        # JWT testing hints
        if any("jwt" in str(req).lower() for req in endpoint.get("auth_requirements", [])):
            hints.append("jwt_testable")
        
        # Privilege escalation hints
        if any(keyword in path for keyword in ["admin", "internal", "config", "settings"]):
            hints.append("privilege_escalation_risk")
        
        # Data exposure hints
        if method == "GET" and any(keyword in path for keyword in ["list", "all", "dump", "export"]):
            hints.append("data_exposure_risk")
        
        # Remove duplicates
        return list(set(hints))
    
    def _deduplicate_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate endpoints based on method and path template."""
        seen = set()
        unique_endpoints = []
        
        for endpoint in endpoints:
            key = (endpoint.get("method"), endpoint.get("path_template"))
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(endpoint)
            else:
                # Merge information from duplicate endpoints
                existing = next(e for e in unique_endpoints if (e.get("method"), e.get("path_template")) == key)
                self._merge_endpoint_info(existing, endpoint)
        
        return unique_endpoints
    
    def _merge_endpoint_info(self, existing: Dict[str, Any], new: Dict[str, Any]) -> None:
        """Merge information from a duplicate endpoint into the existing one."""
        # Merge security hints
        existing_hints = set(existing.get("security_hints", []))
        new_hints = set(new.get("security_hints", []))
        existing["security_hints"] = list(existing_hints | new_hints)
        
        # Merge auth requirements
        existing_auth = set(str(a) for a in existing.get("auth_requirements", []))
        new_auth = set(str(a) for a in new.get("auth_requirements", []))
        all_auth = existing_auth | new_auth
        existing["auth_requirements"] = list(all_auth)
        
        # Update auth detected if new endpoint has auth
        if new.get("auth_detected", False):
            existing["auth_detected"] = True
        
        # Merge parameters (avoid duplicates)
        existing_params = existing.get("parameters", [])
        new_params = new.get("parameters", [])
        
        for new_param in new_params:
            if not any(p.get("name") == new_param.get("name") and p.get("in") == new_param.get("in") 
                      for p in existing_params):
                existing_params.append(new_param)
        
        existing["parameters"] = existing_params
