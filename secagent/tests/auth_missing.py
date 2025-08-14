"""
Authentication bypass testing.
"""

import re
from typing import Dict, Any
import httpx

class AuthBypassTester:
    """Tests for authentication bypass vulnerabilities."""
    
    def execute_test(self, test_case: Dict[str, Any], timeout_ms: int = 8000) -> Dict[str, Any]:
        """Execute authentication bypass test case."""
        
        test_id = test_case.get('id')
        endpoint_id = test_case.get('endpoint_id')
        test_name = test_case.get('test_name')
        method = test_case.get('method', 'GET')
        url = test_case.get('url')
        headers = test_case.get('headers', {})
        
        try:
            # Step 1: Make baseline request with authentication (if available)
            baseline_response = self._make_authenticated_request(method, url, timeout_ms)
            
            # Step 2: Make test request without/with modified authentication
            test_response = self._make_request(method, url, headers, {}, timeout_ms)
            
            # Step 3: Analyze responses for auth bypass
            analysis = self._analyze_auth_responses(baseline_response, test_response, test_name)
            
            return {
                "id": test_id,
                "endpoint_id": endpoint_id,
                "test_type": "auth_bypass",
                "test_name": test_name,
                "status": analysis["status"],
                "severity": analysis["severity"],
                "evidence": analysis["evidence"],
                "request_data": {
                    "method": method,
                    "url": url,
                    "headers": self._mask_sensitive_headers(headers),
                    "auth_modification": self._describe_auth_modification(test_name, headers)
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
                "test_type": "auth_bypass",
                "test_name": test_name,
                "status": "error",
                "error": str(e),
                "evidence": {},
                "request_data": {"method": method, "url": url},
                "response_data": {}
            }
    
    def _make_authenticated_request(self, method: str, url: str, timeout_ms: int) -> Dict[str, Any]:
        """Make baseline request with proper authentication."""
        # This would use the original auth headers from the test plan
        # For now, we'll simulate a successful authenticated response
        try:
            return self._make_request(method, url, {}, {}, timeout_ms)
        except Exception:
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
    
    def _analyze_auth_responses(self, baseline: Dict[str, Any], test: Dict[str, Any], 
                               test_name: str) -> Dict[str, Any]:
        """Analyze responses to detect authentication bypass."""
        
        baseline_status = baseline.get("status_code", 0)
        test_status = test.get("status_code", 0)
        baseline_content = baseline.get("content", "")
        test_content = test.get("content", "")
        
        evidence = {
            "baseline_status": baseline_status,
            "test_status": test_status,
            "baseline_content_length": len(baseline_content),
            "test_content_length": len(test_content),
            "test_description": test_name
        }
        
        # Analysis logic
        if test_status == 0:
            return {"status": "error", "severity": "info", "evidence": evidence}
        
        # Successful response without authentication suggests bypass
        if test_status == 200:
            # Check if we got meaningful content
            if len(test_content) > 100:  # Arbitrary threshold for meaningful content
                evidence["vulnerability_type"] = "authentication_bypass"
                evidence["access_granted"] = True
                
                # Check for sensitive data patterns
                sensitive_patterns = [
                    r'"(?:id|user_id|email|username)"\s*:\s*"[^"]+',
                    r'"(?:token|key|secret)"\s*:\s*"[^"]+',
                    r'"(?:role|permissions|admin)"\s*:\s*"[^"]+',
                    r'\b(?:admin|user|customer)\b.*\b(?:data|info|details)\b'
                ]
                
                sensitive_data_found = any(re.search(pattern, test_content, re.IGNORECASE) 
                                         for pattern in sensitive_patterns)
                
                if sensitive_data_found:
                    evidence["sensitive_data_exposed"] = True
                    return {
                        "status": "vulnerable",
                        "severity": "high",
                        "evidence": evidence
                    }
                else:
                    return {
                        "status": "vulnerable",
                        "severity": "medium",
                        "evidence": evidence
                    }
        
        # Partial success codes might indicate partial bypass
        elif test_status in [201, 202, 204]:
            evidence["partial_access"] = True
            return {
                "status": "vulnerable",
                "severity": "medium",
                "evidence": evidence
            }
        
        # Expected behavior: access denied
        elif test_status in [401, 403]:
            evidence["access_properly_denied"] = True
            return {"status": "secure", "severity": "info", "evidence": evidence}
        
        # Redirects might indicate different handling
        elif test_status in [301, 302, 307, 308]:
            evidence["redirect_response"] = True
            evidence["location"] = test.get("headers", {}).get("location", "")
            
            # Check if redirect goes to login page (good) or elsewhere (potentially bad)
            location = evidence["location"].lower()
            if any(keyword in location for keyword in ["login", "auth", "signin"]):
                return {"status": "secure", "severity": "info", "evidence": evidence}
            else:
                return {
                    "status": "inconclusive",
                    "severity": "low",
                    "evidence": evidence
                }
        
        # Not found might be intentional obfuscation or actual missing endpoint
        elif test_status == 404:
            evidence["endpoint_not_found"] = True
            return {"status": "inconclusive", "severity": "low", "evidence": evidence}
        
        # Server errors
        elif test_status >= 500:
            evidence["server_error"] = True
            return {"status": "inconclusive", "severity": "low", "evidence": evidence}
        
        # Other responses
        else:
            evidence["unexpected_status"] = True
            return {"status": "inconclusive", "severity": "low", "evidence": evidence}
    
    def _describe_auth_modification(self, test_name: str, headers: Dict[str, str]) -> str:
        """Describe what authentication modification was made."""
        
        if "Missing Authorization" in test_name:
            return "Removed Authorization header"
        elif "Invalid Authorization" in test_name:
            auth_header = headers.get("Authorization", "")
            if "Bearer invalid" in auth_header:
                return "Invalid Bearer token"
            elif "Bearer " == auth_header:
                return "Empty Bearer token"
            elif "Basic invalid" in auth_header:
                return "Invalid Basic auth"
            else:
                return f"Modified Authorization: {auth_header[:20]}..."
        else:
            return "Unknown modification"
    
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
