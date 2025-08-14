"""
Active security testing - test planning and execution.
"""

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import httpx
from rich.console import Console
from rich.progress import Progress, TaskID

console = Console()

class TestPlanner:
    """Creates test plans for active security testing."""
    
    def __init__(self, base_url: str, auth_header: Optional[str] = None, 
                 jwt_hint: str = "header", unsafe: bool = False):
        self.base_url = base_url.rstrip('/')
        self.auth_header = auth_header
        self.jwt_hint = jwt_hint
        self.unsafe = unsafe
        
        # Parse auth header
        self.auth_headers = {}
        if auth_header:
            if ':' in auth_header:
                key, value = auth_header.split(':', 1)
                self.auth_headers[key.strip()] = value.strip()
            else:
                self.auth_headers['Authorization'] = auth_header
    
    def create_plan(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create a comprehensive test plan for all endpoints."""
        plan = []
        
        for endpoint in endpoints:
            # Generate test cases for this endpoint
            test_cases = self._generate_endpoint_tests(endpoint)
            plan.extend(test_cases)
        
        return plan
    
    def _generate_endpoint_tests(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate test cases for a single endpoint."""
        tests = []
        
        method = endpoint.get('method', 'GET')
        path = endpoint.get('path', '/')
        endpoint_id = endpoint.get('id')
        security_hints = endpoint.get('security_hints', [])
        id_params = endpoint.get('id_parameters', [])
        auth_detected = endpoint.get('auth_detected', False)
        
        # Build full URL
        full_url = urljoin(self.base_url, path.lstrip('/'))
        
        # 1. BOLA/IDOR Tests
        if 'bola_testable' in security_hints and id_params:
            bola_tests = self._create_bola_tests(endpoint_id, full_url, method, id_params)
            tests.extend(bola_tests)
        
        # 2. Authentication Bypass Tests
        if auth_detected or self.auth_headers:
            auth_tests = self._create_auth_tests(endpoint_id, full_url, method)
            tests.extend(auth_tests)
        
        # 3. JWT Manipulation Tests
        if 'jwt_testable' in security_hints or self._has_jwt_auth():
            jwt_tests = self._create_jwt_tests(endpoint_id, full_url, method)
            tests.extend(jwt_tests)
        
        return tests
    
    def _create_bola_tests(self, endpoint_id: str, url: str, method: str, 
                          id_params: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create BOLA (Broken Object Level Authorization) test cases."""
        tests = []
        
        for param in id_params:
            if not param.get('bola_testable', False):
                continue
            
            param_name = param.get('name')
            param_location = param.get('in')
            
            # Test case 1: Increment ID by 1
            test_id = str(uuid.uuid4())
            tests.append({
                "id": test_id,
                "endpoint_id": endpoint_id,
                "test_type": "bola",
                "test_name": f"BOLA ID increment - {param_name}",
                "method": method,
                "url": url,
                "headers": self.auth_headers.copy(),
                "parameter_mutations": [{
                    "name": param_name,
                    "location": param_location,
                    "mutation_type": "increment",
                    "original_value": None,  # Will be determined at runtime
                    "test_value": None  # Will be calculated at runtime
                }],
                "checks": ["response_status", "response_content", "data_leakage"],
                "safety": {"unsafe": self.unsafe, "mutating": method in ["POST", "PUT", "PATCH", "DELETE"]},
                "expected_outcome": "access_denied"
            })
            
            # Test case 2: Try common ID values
            common_ids = ["1", "2", "admin", "0", "-1", "999999"]
            for test_id_val in common_ids:
                test_id = str(uuid.uuid4())
                tests.append({
                    "id": test_id,
                    "endpoint_id": endpoint_id,
                    "test_type": "bola",
                    "test_name": f"BOLA common ID - {param_name}={test_id_val}",
                    "method": method,
                    "url": url,
                    "headers": self.auth_headers.copy(),
                    "parameter_mutations": [{
                        "name": param_name,
                        "location": param_location,
                        "mutation_type": "replace",
                        "test_value": test_id_val
                    }],
                    "checks": ["response_status", "response_content", "data_leakage"],
                    "safety": {"unsafe": self.unsafe, "mutating": method in ["POST", "PUT", "PATCH", "DELETE"]},
                    "expected_outcome": "access_denied"
                })
        
        return tests
    
    def _create_auth_tests(self, endpoint_id: str, url: str, method: str) -> List[Dict[str, Any]]:
        """Create authentication bypass test cases."""
        tests = []
        
        # Test case 1: Remove Authorization header
        test_id = str(uuid.uuid4())
        headers_no_auth = {k: v for k, v in self.auth_headers.items() 
                          if k.lower() != 'authorization'}
        
        tests.append({
            "id": test_id,
            "endpoint_id": endpoint_id,
            "test_type": "auth_bypass",
            "test_name": "Missing Authorization header",
            "method": method,
            "url": url,
            "headers": headers_no_auth,
            "parameter_mutations": [],
            "checks": ["response_status", "access_control"],
            "safety": {"unsafe": self.unsafe, "mutating": method in ["POST", "PUT", "PATCH", "DELETE"]},
            "expected_outcome": "access_denied"
        })
        
        # Test case 2: Invalid/malformed Authorization header
        if 'Authorization' in self.auth_headers:
            invalid_auths = [
                "Bearer invalid_token",
                "Bearer ",
                "Basic invalid",
                "Invalid format",
                ""
            ]
            
            for invalid_auth in invalid_auths:
                test_id = str(uuid.uuid4())
                headers_invalid = self.auth_headers.copy()
                headers_invalid['Authorization'] = invalid_auth
                
                tests.append({
                    "id": test_id,
                    "endpoint_id": endpoint_id,
                    "test_type": "auth_bypass",
                    "test_name": f"Invalid Authorization - {invalid_auth[:20]}...",
                    "method": method,
                    "url": url,
                    "headers": headers_invalid,
                    "parameter_mutations": [],
                    "checks": ["response_status", "access_control"],
                    "safety": {"unsafe": self.unsafe, "mutating": method in ["POST", "PUT", "PATCH", "DELETE"]},
                    "expected_outcome": "access_denied"
                })
        
        return tests
    
    def _create_jwt_tests(self, endpoint_id: str, url: str, method: str) -> List[Dict[str, Any]]:
        """Create JWT manipulation test cases."""
        tests = []
        
        if not self._has_jwt_auth():
            return tests
        
        # Test case 1: JWT with alg:none
        test_id = str(uuid.uuid4())
        tests.append({
            "id": test_id,
            "endpoint_id": endpoint_id,
            "test_type": "jwt_manipulation",
            "test_name": "JWT algorithm none bypass",
            "method": method,
            "url": url,
            "headers": self.auth_headers.copy(),
            "parameter_mutations": [],
            "jwt_mutations": [{
                "type": "algorithm_none",
                "description": "Change algorithm to 'none' and remove signature"
            }],
            "checks": ["response_status", "jwt_acceptance", "privilege_escalation"],
            "safety": {"unsafe": self.unsafe, "mutating": method in ["POST", "PUT", "PATCH", "DELETE"]},
            "expected_outcome": "access_denied"
        })
        
        # Test case 2: JWT claim manipulation
        test_id = str(uuid.uuid4())
        tests.append({
            "id": test_id,
            "endpoint_id": endpoint_id,
            "test_type": "jwt_manipulation",
            "test_name": "JWT privilege escalation",
            "method": method,
            "url": url,
            "headers": self.auth_headers.copy(),
            "parameter_mutations": [],
            "jwt_mutations": [{
                "type": "claim_manipulation",
                "description": "Add admin role to JWT claims",
                "claims": {"role": "admin", "admin": True, "is_admin": True}
            }],
            "checks": ["response_status", "jwt_acceptance", "privilege_escalation"],
            "safety": {"unsafe": self.unsafe, "mutating": method in ["POST", "PUT", "PATCH", "DELETE"]},
            "expected_outcome": "access_denied"
        })
        
        return tests
    
    def _has_jwt_auth(self) -> bool:
        """Check if JWT authentication is being used."""
        auth_header = self.auth_headers.get('Authorization', '')
        return 'Bearer' in auth_header and len(auth_header.split('.')) >= 2
    
    def save_plan(self, plan: List[Dict[str, Any]], plan_file: Path) -> None:
        """Save test plan to JSONL file."""
        with open(plan_file, 'w') as f:
            for test_case in plan:
                f.write(json.dumps(test_case) + '\n')

class LocalExecutor:
    """Executes security tests locally with rate limiting and safety controls."""
    
    def __init__(self, concurrency: int = 3, delay_ms: int = 200, 
                 timeout_ms: int = 8000, run_dir: Path = None, verbose: bool = False):
        self.concurrency = concurrency
        self.delay_ms = delay_ms
        self.timeout_ms = timeout_ms
        self.run_dir = run_dir
        self.verbose = verbose
        
        # Import test modules
        from .tests.bola import BOLATester
        from .tests.auth_missing import AuthBypassTester
        from .tests.jwt_manip import JWTManipulationTester
        
        self.testers = {
            'bola': BOLATester(),
            'auth_bypass': AuthBypassTester(),
            'jwt_manipulation': JWTManipulationTester()
        }
    
    def execute_plan(self, plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute test plan locally with safety controls."""
        results = []
        
        # Filter tests based on safety settings
        safe_tests = self._filter_safe_tests(plan)
        
        if self.verbose:
            console.print(f"   Executing {len(safe_tests)} tests (filtered from {len(plan)} total)")
        
        # Execute tests with progress tracking
        with Progress() as progress:
            task = progress.add_task("Running security tests...", total=len(safe_tests))
            
            for test_case in safe_tests:
                try:
                    result = self._execute_single_test(test_case)
                    results.append(result)
                    
                    # Rate limiting
                    if self.delay_ms > 0:
                        time.sleep(self.delay_ms / 1000.0)
                    
                    progress.advance(task)
                    
                except Exception as e:
                    error_result = {
                        "id": test_case.get('id'),
                        "endpoint_id": test_case.get('endpoint_id'),
                        "test_type": test_case.get('test_type'),
                        "test_name": test_case.get('test_name'),
                        "status": "error",
                        "error": str(e),
                        "timing_ms": 0
                    }
                    results.append(error_result)
                    
                    if self.verbose:
                        console.print(f"   ❌ Test failed: {test_case.get('test_name')}: {e}", style="red")
                    
                    progress.advance(task)
        
        # Save results
        if self.run_dir:
            results_file = self.run_dir / "tests.jsonl"
            with open(results_file, 'w') as f:
                for result in results:
                    f.write(json.dumps(result, default=str) + '\n')
        
        return results
    
    def _filter_safe_tests(self, plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter tests based on safety settings."""
        safe_tests = []
        
        for test_case in plan:
            safety = test_case.get('safety', {})
            is_mutating = safety.get('mutating', False)
            unsafe_allowed = safety.get('unsafe', False)
            
            # Skip mutating operations unless unsafe mode is enabled
            if is_mutating and not unsafe_allowed:
                if self.verbose:
                    console.print(f"   ⚠️  Skipping mutating test (use --unsafe): {test_case.get('test_name')}", style="yellow")
                continue
            
            safe_tests.append(test_case)
        
        return safe_tests
    
    def _execute_single_test(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single test case."""
        test_type = test_case.get('test_type')
        tester = self.testers.get(test_type)
        
        if not tester:
            raise ValueError(f"Unknown test type: {test_type}")
        
        start_time = time.time()
        
        try:
            result = tester.execute_test(test_case, timeout_ms=self.timeout_ms)
            result['timing_ms'] = int((time.time() - start_time) * 1000)
            return result
            
        except Exception as e:
            return {
                "id": test_case.get('id'),
                "endpoint_id": test_case.get('endpoint_id'),
                "test_type": test_type,
                "test_name": test_case.get('test_name'),
                "status": "error",
                "error": str(e),
                "timing_ms": int((time.time() - start_time) * 1000)
            }

# Modal integration removed - this is a local-first AI security agent
# Users can clone and run locally with their own Ollama installation
