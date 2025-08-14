"""
JWT manipulation testing.
"""

import base64
import json
import re
from typing import Dict, Any, Optional
import httpx

class JWTManipulationTester:
    """Tests for JWT manipulation vulnerabilities."""
    
    def execute_test(self, test_case: Dict[str, Any], timeout_ms: int = 8000) -> Dict[str, Any]:
        """Execute JWT manipulation test case."""
        
        test_id = test_case.get('id')
        endpoint_id = test_case.get('endpoint_id')
        test_name = test_case.get('test_name')
        method = test_case.get('method', 'GET')
        url = test_case.get('url')
        headers = test_case.get('headers', {})
        jwt_mutations = test_case.get('jwt_mutations', [])
        
        try:
            # Step 1: Extract JWT from headers
            original_jwt = self._extract_jwt(headers)
            if not original_jwt:
                return {
                    "id": test_id,
                    "endpoint_id": endpoint_id,
                    "test_type": "jwt_manipulation",
                    "test_name": test_name,
                    "status": "inconclusive",
                    "severity": "info",
                    "evidence": {"error": "No JWT found in request"},
                    "request_data": {"method": method, "url": url},
                    "response_data": {}
                }
            
            # Step 2: Make baseline request with original JWT
            baseline_response = self._make_request(method, url, headers, {}, timeout_ms)
            
            # Step 3: Apply JWT mutations
            mutated_headers = self._apply_jwt_mutations(headers, original_jwt, jwt_mutations)
            
            # Step 4: Make test request with manipulated JWT
            test_response = self._make_request(method, url, mutated_headers, {}, timeout_ms)
            
            # Step 5: Analyze responses for JWT vulnerabilities
            analysis = self._analyze_jwt_responses(
                baseline_response, test_response, original_jwt, jwt_mutations
            )
            
            return {
                "id": test_id,
                "endpoint_id": endpoint_id,
                "test_type": "jwt_manipulation",
                "test_name": test_name,
                "status": analysis["status"],
                "severity": analysis["severity"],
                "evidence": analysis["evidence"],
                "request_data": {
                    "method": method,
                    "url": url,
                    "headers": self._mask_sensitive_headers(mutated_headers),
                    "jwt_mutations": jwt_mutations
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
                "test_type": "jwt_manipulation",
                "test_name": test_name,
                "status": "error",
                "error": str(e),
                "evidence": {},
                "request_data": {"method": method, "url": url},
                "response_data": {}
            }
    
    def _extract_jwt(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract JWT token from request headers."""
        
        # Check Authorization header
        auth_header = headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()
            if self._is_jwt(token):
                return token
        
        # Check other common JWT header names
        jwt_headers = ['X-Auth-Token', 'X-JWT-Token', 'Access-Token']
        for header_name in jwt_headers:
            token = headers.get(header_name, '')
            if self._is_jwt(token):
                return token
        
        # Check cookies (simplified - would need proper cookie parsing)
        cookie_header = headers.get('Cookie', '')
        jwt_match = re.search(r'(?:jwt|token|auth)=([^;]+)', cookie_header, re.IGNORECASE)
        if jwt_match:
            token = jwt_match.group(1)
            if self._is_jwt(token):
                return token
        
        return None
    
    def _is_jwt(self, token: str) -> bool:
        """Check if a string looks like a JWT token."""
        if not token:
            return False
        
        parts = token.split('.')
        return len(parts) >= 2  # JWT has at least header.payload (signature optional)
    
    def _apply_jwt_mutations(self, headers: Dict[str, str], original_jwt: str, 
                           mutations: list) -> Dict[str, str]:
        """Apply JWT mutations to headers."""
        
        mutated_headers = headers.copy()
        
        for mutation in mutations:
            mutation_type = mutation.get('type')
            
            if mutation_type == 'algorithm_none':
                mutated_jwt = self._create_alg_none_jwt(original_jwt)
            elif mutation_type == 'claim_manipulation':
                claims = mutation.get('claims', {})
                mutated_jwt = self._manipulate_jwt_claims(original_jwt, claims)
            else:
                continue  # Unknown mutation type
            
            # Replace JWT in headers
            mutated_headers = self._replace_jwt_in_headers(mutated_headers, mutated_jwt)
        
        return mutated_headers
    
    def _create_alg_none_jwt(self, original_jwt: str) -> str:
        """Create JWT with algorithm 'none' (no signature)."""
        
        try:
            parts = original_jwt.split('.')
            if len(parts) < 2:
                return original_jwt
            
            # Decode header
            header_data = self._decode_jwt_part(parts[0])
            if not header_data:
                return original_jwt
            
            # Modify algorithm to 'none'
            header_data['alg'] = 'none'
            
            # Encode new header
            new_header = self._encode_jwt_part(header_data)
            
            # Keep original payload
            payload = parts[1]
            
            # Create JWT with no signature (algorithm 'none')
            return f"{new_header}.{payload}."
            
        except Exception:
            return original_jwt
    
    def _manipulate_jwt_claims(self, original_jwt: str, new_claims: Dict[str, Any]) -> str:
        """Manipulate JWT claims (payload)."""
        
        try:
            parts = original_jwt.split('.')
            if len(parts) < 2:
                return original_jwt
            
            # Decode payload
            payload_data = self._decode_jwt_part(parts[1])
            if not payload_data:
                return original_jwt
            
            # Add/modify claims
            payload_data.update(new_claims)
            
            # Encode new payload
            new_payload = self._encode_jwt_part(payload_data)
            
            # Keep original header
            header = parts[0]
            
            # Keep original signature (will be invalid, but that's the test)
            signature = parts[2] if len(parts) > 2 else ""
            
            return f"{header}.{new_payload}.{signature}"
            
        except Exception:
            return original_jwt
    
    def _decode_jwt_part(self, part: str) -> Optional[Dict[str, Any]]:
        """Decode JWT part (header or payload)."""
        
        try:
            # Add padding if needed
            padding = 4 - (len(part) % 4)
            if padding != 4:
                part += '=' * padding
            
            # Decode base64
            decoded_bytes = base64.urlsafe_b64decode(part)
            
            # Parse JSON
            return json.loads(decoded_bytes.decode('utf-8'))
            
        except Exception:
            return None
    
    def _encode_jwt_part(self, data: Dict[str, Any]) -> str:
        """Encode JWT part (header or payload)."""
        
        try:
            # Convert to JSON
            json_str = json.dumps(data, separators=(',', ':'))
            
            # Encode to base64
            encoded_bytes = base64.urlsafe_b64encode(json_str.encode('utf-8'))
            
            # Remove padding
            return encoded_bytes.decode('utf-8').rstrip('=')
            
        except Exception:
            return ""
    
    def _replace_jwt_in_headers(self, headers: Dict[str, str], new_jwt: str) -> Dict[str, str]:
        """Replace JWT token in headers."""
        
        mutated = headers.copy()
        
        # Replace in Authorization header
        if 'Authorization' in mutated and mutated['Authorization'].startswith('Bearer '):
            mutated['Authorization'] = f"Bearer {new_jwt}"
            return mutated
        
        # Replace in other JWT headers
        jwt_headers = ['X-Auth-Token', 'X-JWT-Token', 'Access-Token']
        for header_name in jwt_headers:
            if header_name in mutated and self._is_jwt(mutated[header_name]):
                mutated[header_name] = new_jwt
                return mutated
        
        return mutated
    
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
    
    def _analyze_jwt_responses(self, baseline: Dict[str, Any], test: Dict[str, Any], 
                              original_jwt: str, mutations: list) -> Dict[str, Any]:
        """Analyze responses to detect JWT vulnerabilities."""
        
        baseline_status = baseline.get("status_code", 0)
        test_status = test.get("status_code", 0)
        baseline_content = baseline.get("content", "")
        test_content = test.get("content", "")
        
        evidence = {
            "baseline_status": baseline_status,
            "test_status": test_status,
            "baseline_content_length": len(baseline_content),
            "test_content_length": len(test_content),
            "mutations_applied": mutations,
            "jwt_parts": len(original_jwt.split('.'))
        }
        
        # Analysis logic
        if test_status == 0:
            return {"status": "error", "severity": "info", "evidence": evidence}
        
        # Successful response with manipulated JWT suggests vulnerability
        if test_status == 200:
            mutation_type = mutations[0].get('type') if mutations else 'unknown'
            
            if mutation_type == 'algorithm_none':
                evidence["vulnerability_type"] = "jwt_algorithm_confusion"
                evidence["accepts_unsigned_jwt"] = True
                return {
                    "status": "vulnerable",
                    "severity": "high",
                    "evidence": evidence
                }
            
            elif mutation_type == 'claim_manipulation':
                # Check if we got elevated privileges
                privilege_indicators = [
                    r'"role"\s*:\s*"admin"',
                    r'"admin"\s*:\s*true',
                    r'"is_admin"\s*:\s*true',
                    r'"permissions"\s*:\s*\[[^\]]*"admin"',
                    r'admin.*dashboard',
                    r'administrative.*access'
                ]
                
                has_elevated_access = any(re.search(pattern, test_content, re.IGNORECASE) 
                                        for pattern in privilege_indicators)
                
                if has_elevated_access:
                    evidence["vulnerability_type"] = "jwt_privilege_escalation"
                    evidence["elevated_privileges_detected"] = True
                    return {
                        "status": "vulnerable",
                        "severity": "high",
                        "evidence": evidence
                    }
                else:
                    evidence["vulnerability_type"] = "jwt_claim_manipulation"
                    evidence["accepts_modified_claims"] = True
                    return {
                        "status": "vulnerable",
                        "severity": "medium",
                        "evidence": evidence
                    }
        
        # Expected behavior: JWT validation should fail
        elif test_status in [401, 403]:
            evidence["jwt_properly_validated"] = True
            return {"status": "secure", "severity": "info", "evidence": evidence}
        
        # Server errors might indicate JWT parsing issues
        elif test_status >= 500:
            evidence["server_error"] = True
            evidence["potential_jwt_parsing_error"] = True
            return {"status": "inconclusive", "severity": "low", "evidence": evidence}
        
        # Other responses
        else:
            evidence["unexpected_response"] = True
            return {"status": "inconclusive", "severity": "low", "evidence": evidence}
    
    def _mask_sensitive_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Mask sensitive information in headers."""
        masked = {}
        sensitive_headers = ['authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-jwt-token']
        
        for key, value in headers.items():
            if key.lower() in sensitive_headers:
                if len(value) > 20:
                    masked[key] = value[:8] + "..." + value[-8:]
                else:
                    masked[key] = "***"
            else:
                masked[key] = value
        
        return masked
