"""
Modal-powered distributed security testing for rAPId Security Agent.

This module provides cloud-scale security testing capabilities using Modal's
distributed computing platform. It allows for parallel execution of security
tests across multiple containers, dramatically improving performance for
large-scale API security assessments.
"""

import json
import modal
from typing import Dict, List, Any, Optional
from pathlib import Path
import tempfile
import os

# Create Modal app
app = modal.App("rapid-security-agent")

# Define the Modal image with all required dependencies
image = (
    modal.Image.debian_slim()
    .pip_install([
        "httpx>=0.25.0",
        "pydantic>=2.0.0",
        "typer>=0.9.0",
        "rich>=13.0.0",
        "semgrep>=1.45.0",
        "sqlalchemy>=2.0.0",
        "jinja2>=3.1.0",
        "python-multipart>=0.0.6",
        "gitpython>=3.1.0",
        "pyyaml>=6.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0"
    ])
    .apt_install(["git", "curl"])
)

@app.function(
    image=image,
    cpu=2.0,
    memory=4096,
    timeout=3600,
    max_containers=50
)
def distributed_security_test(
    endpoint_batch: List[Dict[str, Any]],
    base_url: str,
    auth_header: Optional[str] = None,
    unsafe: bool = False,
    delay_ms: int = 200
) -> List[Dict[str, Any]]:
    """
    Execute security tests on a batch of endpoints in parallel.
    
    Args:
        endpoint_batch: List of endpoint dictionaries to test
        base_url: Base URL for the API
        auth_header: Optional authentication header
        unsafe: Whether to allow mutating requests
        delay_ms: Delay between requests in milliseconds
    
    Returns:
        List of test results for the batch
    """
    import asyncio
    import httpx
    from datetime import datetime
    import time
    
    async def test_endpoint_batch():
        results = []
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            for endpoint in endpoint_batch:
                try:
                    # Add delay between requests
                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000.0)
                    
                    # Prepare headers
                    headers = {}
                    if auth_header:
                        key, value = auth_header.split(': ', 1)
                        headers[key] = value
                    
                    # Build full URL
                    url = f"{base_url.rstrip('/')}{endpoint['path']}"
                    
                    # Execute security tests for this endpoint
                    endpoint_results = await run_endpoint_security_tests(
                        client, endpoint, url, headers, unsafe
                    )
                    
                    results.extend(endpoint_results)
                    
                except Exception as e:
                    results.append({
                        'endpoint': endpoint['path'],
                        'test_type': 'error',
                        'status': 'error',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
        
        return results
    
    # Run the async batch processing
    return asyncio.run(test_endpoint_batch())

async def run_endpoint_security_tests(
    client,  # httpx.AsyncClient
    endpoint: Dict[str, Any],
    url: str,
    headers: Dict[str, str],
    unsafe: bool
) -> List[Dict[str, Any]]:
    """Run all security tests for a single endpoint."""
    results = []
    
    # Test 1: BOLA/IDOR Testing
    if any(param.get('is_id_like') for param in endpoint.get('params', [])):
        bola_result = await test_bola_vulnerability(client, endpoint, url, headers, unsafe)
        if bola_result:
            results.append(bola_result)
    
    # Test 2: Authentication Bypass
    auth_result = await test_auth_bypass(client, endpoint, url, headers, unsafe)
    if auth_result:
        results.append(auth_result)
    
    # Test 3: JWT Manipulation (if JWT detected)
    if 'authorization' in headers and 'bearer' in headers['authorization'].lower():
        jwt_result = await test_jwt_manipulation(client, endpoint, url, headers, unsafe)
        if jwt_result:
            results.append(jwt_result)
    
    return results

async def test_bola_vulnerability(
    client,  # httpx.AsyncClient
    endpoint: Dict[str, Any],
    url: str,
    headers: Dict[str, str],
    unsafe: bool
) -> Optional[Dict[str, Any]]:
    """Test for BOLA/IDOR vulnerabilities."""
    try:
        # Only test GET requests or if unsafe mode is enabled
        if endpoint['method'].upper() != 'GET' and not unsafe:
            return None
        
        # Find ID-like parameters
        id_params = [p for p in endpoint.get('params', []) if p.get('is_id_like')]
        if not id_params:
            return None
        
        # Test with different ID values
        test_ids = ['1', '999999', 'admin', '0', '-1']
        
        for test_id in test_ids:
            test_url = url
            for param in id_params:
                test_url = test_url.replace(f"{{{param['name']}}}", test_id)
            
            response = await client.request(
                endpoint['method'],
                test_url,
                headers=headers,
                timeout=10.0
            )
            
            # Check for potential BOLA vulnerability
            if response.status_code == 200 and len(response.content) > 100:
                return {
                    'endpoint': endpoint['path'],
                    'test_type': 'bola',
                    'status': 'vulnerable',
                    'details': f'BOLA vulnerability detected with ID: {test_id}',
                    'response_code': response.status_code,
                    'response_size': len(response.content),
                    'test_url': test_url,
                    'timestamp': datetime.now().isoformat()
                }
        
        return {
            'endpoint': endpoint['path'],
            'test_type': 'bola',
            'status': 'secure',
            'details': 'No BOLA vulnerability detected',
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            'endpoint': endpoint['path'],
            'test_type': 'bola',
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

async def test_auth_bypass(
    client,  # httpx.AsyncClient
    endpoint: Dict[str, Any],
    url: str,
    headers: Dict[str, str],
    unsafe: bool
) -> Optional[Dict[str, Any]]:
    """Test for authentication bypass vulnerabilities."""
    try:
        # Only test GET requests or if unsafe mode is enabled
        if endpoint['method'].upper() != 'GET' and not unsafe:
            return None
        
        # Test without authentication headers
        no_auth_headers = {k: v for k, v in headers.items() 
                          if k.lower() not in ['authorization', 'x-api-key', 'x-auth-token']}
        
        response = await client.request(
            endpoint['method'],
            url,
            headers=no_auth_headers,
            timeout=10.0
        )
        
        # Check if endpoint is accessible without auth
        if response.status_code == 200:
            return {
                'endpoint': endpoint['path'],
                'test_type': 'auth_bypass',
                'status': 'vulnerable',
                'details': 'Endpoint accessible without authentication',
                'response_code': response.status_code,
                'timestamp': datetime.now().isoformat()
            }
        
        return {
            'endpoint': endpoint['path'],
            'test_type': 'auth_bypass',
            'status': 'secure',
            'details': 'Authentication required',
            'response_code': response.status_code,
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            'endpoint': endpoint['path'],
            'test_type': 'auth_bypass',
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

async def test_jwt_manipulation(
    client,  # httpx.AsyncClient
    endpoint: Dict[str, Any],
    url: str,
    headers: Dict[str, str],
    unsafe: bool
) -> Optional[Dict[str, Any]]:
    """Test for JWT manipulation vulnerabilities."""
    try:
        # Only test GET requests or if unsafe mode is enabled
        if endpoint['method'].upper() != 'GET' and not unsafe:
            return None
        
        auth_header = headers.get('authorization', '')
        if not auth_header or 'bearer' not in auth_header.lower():
            return None
        
        # Extract JWT token
        token = auth_header.split(' ', 1)[1] if ' ' in auth_header else auth_header
        
        # Test with manipulated JWT (remove signature)
        if '.' in token:
            parts = token.split('.')
            if len(parts) == 3:
                # Test with empty signature
                manipulated_token = f"{parts[0]}.{parts[1]}."
                test_headers = headers.copy()
                test_headers['authorization'] = f"Bearer {manipulated_token}"
                
                response = await client.request(
                    endpoint['method'],
                    url,
                    headers=test_headers,
                    timeout=10.0
                )
                
                # Check if manipulated JWT is accepted
                if response.status_code == 200:
                    return {
                        'endpoint': endpoint['path'],
                        'test_type': 'jwt_manipulation',
                        'status': 'vulnerable',
                        'details': 'JWT signature validation bypassed',
                        'response_code': response.status_code,
                        'timestamp': datetime.now().isoformat()
                    }
        
        return {
            'endpoint': endpoint['path'],
            'test_type': 'jwt_manipulation',
            'status': 'secure',
            'details': 'JWT validation appears secure',
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            'endpoint': endpoint['path'],
            'test_type': 'jwt_manipulation',
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

@app.function(
    image=image,
    cpu=4.0,
    memory=8192,
    timeout=7200,
    max_containers=10
)
def modal_security_scan(
    repo_url: str,
    base_url: str,
    auth_header: Optional[str] = None,
    unsafe: bool = False,
    concurrency: int = 10,
    delay_ms: int = 200
) -> Dict[str, Any]:
    """
    Main Modal function to orchestrate distributed security scanning.
    
    Args:
        repo_url: GitHub repository URL to analyze
        base_url: Base URL for the API to test
        auth_header: Optional authentication header
        unsafe: Whether to allow mutating requests
        concurrency: Number of parallel test batches
        delay_ms: Delay between requests in milliseconds
    
    Returns:
        Complete security scan results
    """
    import tempfile
    import subprocess
    from datetime import datetime
    
    # Create temporary directory for this scan
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Clone the repository
        print(f"🔄 Cloning repository: {repo_url}")
        subprocess.run([
            "git", "clone", "--depth", "1", repo_url, str(temp_path / "repo")
        ], check=True, capture_output=True)
        
        # Import and run discovery (simplified version)
        endpoints = discover_endpoints_modal(temp_path / "repo")
        
        if not endpoints:
            return {
                'status': 'completed',
                'endpoints_found': 0,
                'tests_executed': 0,
                'vulnerabilities': [],
                'summary': 'No API endpoints discovered in repository',
                'timestamp': datetime.now().isoformat()
            }
        
        print(f"🎯 Found {len(endpoints)} endpoints, starting distributed testing...")
        
        # Split endpoints into batches for parallel processing
        batch_size = max(1, len(endpoints) // concurrency)
        endpoint_batches = [
            endpoints[i:i + batch_size] 
            for i in range(0, len(endpoints), batch_size)
        ]
        
        # Execute distributed testing
        all_results = []
        for batch in endpoint_batches:
            batch_results = distributed_security_test.remote(
                batch, base_url, auth_header, unsafe, delay_ms
            )
            all_results.extend(batch_results)
        
        # Analyze results
        vulnerabilities = [r for r in all_results if r.get('status') == 'vulnerable']
        
        return {
            'status': 'completed',
            'endpoints_found': len(endpoints),
            'tests_executed': len(all_results),
            'vulnerabilities': vulnerabilities,
            'vulnerability_count': len(vulnerabilities),
            'all_results': all_results,
            'summary': f"Tested {len(endpoints)} endpoints, found {len(vulnerabilities)} vulnerabilities",
            'timestamp': datetime.now().isoformat(),
            'modal_execution': True
        }

def discover_endpoints_modal(repo_path: Path) -> List[Dict[str, Any]]:
    """
    Simplified endpoint discovery for Modal execution.
    This is a lightweight version of the full discovery logic.
    """
    endpoints = []
    
    # Look for common API patterns in files
    for file_path in repo_path.rglob("*.py"):
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Simple FastAPI detection
            if 'fastapi' in content.lower() or '@app.' in content:
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if any(method in line for method in ['@app.get', '@app.post', '@app.put', '@app.delete']):
                        # Extract path from decorator
                        if '("' in line and '")' in line:
                            path = line.split('("')[1].split('")')[0]
                            method = line.split('@app.')[1].split('(')[0].upper()
                            
                            # Check for ID-like parameters
                            params = []
                            if '{' in path and '}' in path:
                                import re
                                param_matches = re.findall(r'\{([^}]+)\}', path)
                                for param in param_matches:
                                    params.append({
                                        'name': param,
                                        'is_id_like': any(id_word in param.lower() 
                                                        for id_word in ['id', 'uuid', 'key'])
                                    })
                            
                            endpoints.append({
                                'path': path,
                                'method': method,
                                'params': params,
                                'source': str(file_path.relative_to(repo_path))
                            })
            
        except Exception:
            continue
    
    return endpoints

@app.local_entrypoint()
def main(
    repo_url: str,
    base_url: str,
    auth_header: str = None,
    unsafe: bool = False,
    concurrency: int = 10,
    delay_ms: int = 200
):
    """
    Local entrypoint for Modal security scanning.
    This can be called from the CLI or other local code.
    """
    print("🚀 Starting Modal-powered distributed security scan...")
    
    result = modal_security_scan.remote(
        repo_url=repo_url,
        base_url=base_url,
        auth_header=auth_header,
        unsafe=unsafe,
        concurrency=concurrency,
        delay_ms=delay_ms
    )
    
    print(f"✅ Scan completed: {result['summary']}")
    return result

if __name__ == "__main__":
    # Example usage
    result = main(
        repo_url="https://github.com/user/api-project",
        base_url="https://api.example.com",
        auth_header="Authorization: Bearer token123"
    )
    print(json.dumps(result, indent=2))
