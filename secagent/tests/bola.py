"""
BOLA (Broken Object Level Authorization) / IDOR testing.
"""

import re
import uuid
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx

class BOLATester:
    """Tests for Broken Object Level Authorization vulnerabilities."""
    
    def execute_test(self, test_case: Dict[str, Any], timeout_ms: int = 8000) -> Dict[str, Any]:
        """Execute BOLA test case."""
        
        test_id = test_case.get('id')
        endpoint_id = test_case.get('endpoint_id')
        test_name = test_case.get('test_name')
        method = test_case.get('method', 'GET')
        url = test_case.get('url')
        headers = test_case.get('headers', {})
        mutations = test_case.get('parameter_mutations', [])
        
        try:
            # Step 1: Make baseline request with original parameters
            baseline_response = self._make_baseline_request(method, url, headers, timeout_ms)
            
            # Step 2: Apply parameter mutations and test
            mutated_url, mutated_headers, mutated_body = self._apply_mutations(
                url, headers, {}, mutations
            )
            
            # Step 3: Make test request
            test_response = self._make_request(
                method, mutated_url, mutated_headers, mutated_body, timeout_ms
            )
            
            # Step 4: Analyze responses for BOLA vulnerability
            analysis = self._analyze_bola_responses(baseline_response, test_response, mutations)
            
            return {
                "id": test_id,
                "endpoint_id": endpoint_id,
                "test_type": "bola",
                "test_name": test_name,
                "status": analysis["status"],
                "severity": analysis["severity"],
                "evidence": analysis["evidence"],
                "request_data": {
                    "method": method,
                    "url": mutated_url,
                    "headers": self._mask_sensitive_headers(mutated_headers),
                    "mutations": mutations
                },
                "response_data": {
                    "status_code": test_response.get("status_code"),
                    "content_length": test_response.get("content_length"),
                    "response_time_ms": test_response.get("response_time_ms")
                }
            }
            
        except Exception as e:
            return {
                "id": test_id,
                "endpoint_id": endpoint_id,
                "test_type": "bola",
                "test_name": test_name,
                "status": "error",
                "error": str(e),
                "evidence": {},
                "request_data": {"method": method, "url": url},
                "response_data": {}
            }
    
    def _make_baseline_request(self, method: str, url: str, headers: Dict[str, str], 
                              timeout_ms: int) -> Dict[str, Any]:
        """Make baseline request to understand normal behavior."""
        try:
            return self._make_request(method, url, headers, {}, timeout_ms)
        except Exception:
            # If baseline fails, return empty response
            return {"status_code": 0, "content": "", "headers": {}}
    
    def _make_request(self, method: str, url: str, headers: Dict[str, str], 
                     body: Dict[str, Any], timeout_ms: int) -> Dict[str, Any]:
        """Make HTTP request and return structured response."""
        
        timeout_seconds = timeout_ms / 1000.0
        
        with httpx.Client(timeout=timeout_seconds, follow_redirects=True) as client:
            
            request_kwargs = {
                "method": method,
                "url": url,
                "headers": headers
            }
            
            if body and method.upper() in ["POST", "PUT", "PATCH"]:
                request_kwargs["json"] = body
            
            response = client.request(**request_kwargs)
            
            # Extract response data
            content = ""
            try:
                content = response.text[:10000]  # Limit content size
            except Exception:
                content = str(response.content[:10000])
            
            return {
                "status_code": response.status_code,
                "content": content,
                "content_length": len(content),
                "headers": dict(response.headers),
                "response_time_ms": int(response.elapsed.total_seconds() * 1000)
            }
    
    def _apply_mutations(self, url: str, headers: Dict[str, str], body: Dict[str, Any], 
                        mutations: list) -> tuple:
        """Apply parameter mutations to request."""
        
        mutated_url = url
        mutated_headers = headers.copy()
        mutated_body = body.copy()
        
        for mutation in mutations:
            param_name = mutation.get('name')
            param_location = mutation.get('in', mutation.get('location'))
            mutation_type = mutation.get('mutation_type')
            test_value = mutation.get('test_value')
            
            if param_location == 'path':
                mutated_url = self._mutate_path_param(mutated_url, param_name, mutation_type, test_value)
            elif param_location == 'query':
                mutated_url = self._mutate_query_param(mutated_url, param_name, mutation_type, test_value)
            elif param_location == 'header':
                mutated_headers = self._mutate_header_param(mutated_headers, param_name, mutation_type, test_value)
            elif param_location == 'body':
                mutated_body = self._mutate_body_param(mutated_body, param_name, mutation_type, test_value)
        
        return mutated_url, mutated_headers, mutated_body
    
    def _mutate_path_param(self, url: str, param_name: str, mutation_type: str, test_value: Any) -> str:
        """Mutate path parameter."""
        
        if test_value is not None:
            # Direct replacement
            return self._replace_path_segment(url, param_name, str(test_value))
        
        if mutation_type == 'increment':
            # Try to find and increment numeric path segments
            return self._increment_path_ids(url)
        
        return url
    
    def _mutate_query_param(self, url: str, param_name: str, mutation_type: str, test_value: Any) -> str:
        """Mutate query parameter."""
        
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        if test_value is not None:
            query_params[param_name] = [str(test_value)]
        elif mutation_type == 'increment':
            if param_name in query_params:
                try:
                    current_val = int(query_params[param_name][0])
                    query_params[param_name] = [str(current_val + 1)]
                except (ValueError, IndexError):
                    query_params[param_name] = ['2']
        
        # Rebuild URL
        new_query = urlencode(query_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    def _mutate_header_param(self, headers: Dict[str, str], param_name: str, 
                           mutation_type: str, test_value: Any) -> Dict[str, str]:
        """Mutate header parameter."""
        mutated = headers.copy()
        
        if test_value is not None:
            mutated[param_name] = str(test_value)
        
        return mutated
    
    def _mutate_body_param(self, body: Dict[str, Any], param_name: str, 
                          mutation_type: str, test_value: Any) -> Dict[str, Any]:
        """Mutate body parameter."""
        mutated = body.copy()
        
        if test_value is not None:
            mutated[param_name] = test_value
        elif mutation_type == 'increment':
            if param_name in mutated:
                try:
                    current_val = int(mutated[param_name])
                    mutated[param_name] = current_val + 1
                except (ValueError, TypeError):
                    mutated[param_name] = 2
        
        return mutated
    
    def _replace_path_segment(self, url: str, param_name: str, new_value: str) -> str:
        """Replace path segment with new value."""
        
        # Try to find path parameters in various formats
        patterns = [
            (r'\{' + param_name + r'\}', new_value),  # {id}
            (r'<' + param_name + r'>', new_value),     # <id>
            (r':' + param_name, new_value),            # :id
        ]
        
        for pattern, replacement in patterns:
            url = re.sub(pattern, replacement, url)
        
        # If no template found, try to replace numeric segments
        if not any(p[0] in url for p, _ in patterns):
            url = re.sub(r'/\d+(?=/|$)', f'/{new_value}', url, count=1)
        
        return url
    
    def _increment_path_ids(self, url: str) -> str:
        """Increment numeric IDs in path."""
        
        def increment_match(match):
            try:
                current_id = int(match.group(1))
                return f'/{current_id + 1}'
            except ValueError:
                return f'/2'
        
        # Increment first numeric path segment
        return re.sub(r'/(\d+)(?=/|$)', increment_match, url, count=1)
    
    def _analyze_bola_responses(self, baseline: Dict[str, Any], test: Dict[str, Any], 
                               mutations: list) -> Dict[str, Any]:
        """Analyze responses to detect BOLA vulnerability."""
        
        baseline_status = baseline.get("status_code", 0)
        test_status = test.get("status_code", 0)
        baseline_content = baseline.get("content", "")
        test_content = test.get("content", "")
        
        evidence = {
            "baseline_status": baseline_status,
            "test_status": test_status,
            "baseline_content_length": len(baseline_content),
            "test_content_length": len(test_content),
            "mutations_applied": mutations
        }
        
        # Analysis logic
        if test_status == 0:
            return {"status": "error", "severity": "info", "evidence": evidence}
        
        # Successful response to unauthorized request suggests BOLA
        if test_status == 200 and baseline_status == 200:
            # Check if content is similar (potential data leakage)
            content_similarity = self._calculate_content_similarity(baseline_content, test_content)
            
            if content_similarity > 0.8:
                evidence["content_similarity"] = content_similarity
                evidence["vulnerability_type"] = "data_access"
                return {
                    "status": "vulnerable",
                    "severity": "high",
                    "evidence": evidence
                }
            elif content_similarity > 0.3:
                evidence["content_similarity"] = content_similarity
                evidence["vulnerability_type"] = "potential_data_leakage"
                return {
                    "status": "vulnerable",
                    "severity": "medium",
                    "evidence": evidence
                }
        
        # Different successful status codes might indicate partial access
        if test_status in [200, 201, 202] and baseline_status in [200, 201, 202]:
            if test_status != baseline_status:
                evidence["status_code_difference"] = True
                return {
                    "status": "vulnerable",
                    "severity": "medium",
                    "evidence": evidence
                }
        
        # Expected behavior: access denied
        if test_status in [401, 403, 404]:
            return {"status": "secure", "severity": "info", "evidence": evidence}
        
        # Unexpected responses
        if test_status >= 500:
            evidence["server_error"] = True
            return {"status": "inconclusive", "severity": "low", "evidence": evidence}
        
        # Default: inconclusive
        return {"status": "inconclusive", "severity": "low", "evidence": evidence}
    
    def _calculate_content_similarity(self, content1: str, content2: str) -> float:
        """Calculate similarity between two content strings."""
        if not content1 or not content2:
            return 0.0
        
        # Simple similarity based on common words
        words1 = set(re.findall(r'\w+', content1.lower()))
        words2 = set(re.findall(r'\w+', content2.lower()))
        
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        
        return intersection / union if union > 0 else 0.0
    
    def _mask_sensitive_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Mask sensitive information in headers."""
        masked = {}
        sensitive_headers = ['authorization', 'cookie', 'x-api-key', 'x-auth-token']
        
        for key, value in headers.items():
            if key.lower() in sensitive_headers:
                if len(value) > 10:
                    masked[key] = value[:4] + "..." + value[-4:]
                else:
                    masked[key] = "***"
            else:
                masked[key] = value
        
        return masked
