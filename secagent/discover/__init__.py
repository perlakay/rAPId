"""
Static code discovery for API endpoints and security patterns.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from rich.console import Console

from .openapi import OpenAPIDiscovery
from .graphql import GraphQLDiscovery
from .node import NodeDiscovery
from .python import PythonDiscovery

console = Console()

class StaticDiscovery:
    """Orchestrates static discovery across different technologies."""
    
    def __init__(self, repo_path: Path, run_dir: Path, verbose: bool = False):
        self.repo_path = repo_path
        self.run_dir = run_dir
        self.verbose = verbose
        
        # Initialize discovery modules
        self.openapi = OpenAPIDiscovery(repo_path, verbose)
        self.graphql = GraphQLDiscovery(repo_path, verbose)
        self.node = NodeDiscovery(repo_path, verbose)
        self.python = PythonDiscovery(repo_path, verbose)
    
    def discover_all(self, openapi_path: Optional[str] = None, 
                    graphql_endpoint: Optional[str] = None) -> Dict[str, Any]:
        """
        Run all discovery methods and combine results.
        
        Args:
            openapi_path: Explicit OpenAPI spec file path
            graphql_endpoint: GraphQL endpoint path
            
        Returns:
            Combined discovery results
        """
        results = {
            "repo_path": str(self.repo_path),
            "discovery_methods": [],
            "endpoints": [],
            "security_findings": [],
            "technologies": [],
            "metadata": {}
        }
        
        # 1. OpenAPI Discovery (highest priority)
        if self.verbose:
            console.print("   🔍 Searching for OpenAPI specifications...")
        
        openapi_results = self.openapi.discover(explicit_path=openapi_path)
        if openapi_results["specs"]:
            results["discovery_methods"].append("openapi")
            results["endpoints"].extend(openapi_results["endpoints"])
            results["metadata"]["openapi"] = openapi_results
            if self.verbose:
                console.print(f"   ✅ Found {len(openapi_results['endpoints'])} OpenAPI endpoints")
        
        # 2. GraphQL Discovery
        if self.verbose:
            console.print("   🔍 Searching for GraphQL schemas...")
        
        graphql_results = self.graphql.discover(explicit_endpoint=graphql_endpoint)
        if graphql_results["schemas"]:
            results["discovery_methods"].append("graphql")
            results["endpoints"].extend(graphql_results["endpoints"])
            results["metadata"]["graphql"] = graphql_results
            if self.verbose:
                console.print(f"   ✅ Found {len(graphql_results['endpoints'])} GraphQL operations")
        
        # 3. Node.js Framework Discovery
        if self._has_node_files():
            if self.verbose:
                console.print("   🔍 Analyzing Node.js/JavaScript files...")
            
            node_results = self.node.discover()
            if node_results["endpoints"]:
                results["discovery_methods"].append("node")
                results["endpoints"].extend(node_results["endpoints"])
                results["security_findings"].extend(node_results["security_findings"])
                results["technologies"].extend(node_results["technologies"])
                results["metadata"]["node"] = node_results
                if self.verbose:
                    console.print(f"   ✅ Found {len(node_results['endpoints'])} Node.js endpoints")
        
        # 4. Python Framework Discovery
        if self._has_python_files():
            if self.verbose:
                console.print("   🔍 Analyzing Python files...")
            
            python_results = self.python.discover()
            if python_results["endpoints"]:
                results["discovery_methods"].append("python")
                results["endpoints"].extend(python_results["endpoints"])
                results["security_findings"].extend(python_results["security_findings"])
                results["technologies"].extend(python_results["technologies"])
                results["metadata"]["python"] = python_results
                if self.verbose:
                    console.print(f"   ✅ Found {len(python_results['endpoints'])} Python endpoints")
        
        # 5. Optional Semgrep Analysis
        semgrep_results = self._run_semgrep()
        if semgrep_results:
            results["security_findings"].extend(semgrep_results)
            results["metadata"]["semgrep"] = {"findings_count": len(semgrep_results)}
            if self.verbose:
                console.print(f"   ✅ Semgrep found {len(semgrep_results)} security patterns")
        
        # Remove duplicates and finalize
        results["endpoints"] = self._deduplicate_endpoints(results["endpoints"])
        results["technologies"] = list(set(results["technologies"]))
        
        # Save static discovery results
        with open(self.run_dir / "static.json", "w") as f:
            json.dump(results, f, indent=2, default=str)
        
        if self.verbose:
            console.print(f"   📊 Total unique endpoints: {len(results['endpoints'])}")
            console.print(f"   🔧 Technologies detected: {', '.join(results['technologies'])}")
        
        return results
    
    def _has_node_files(self) -> bool:
        """Check if repository contains Node.js files."""
        indicators = [
            "package.json",
            "*.js", "*.ts", "*.jsx", "*.tsx"
        ]
        
        for indicator in indicators:
            if indicator.endswith(".json"):
                if (self.repo_path / indicator).exists():
                    return True
            else:
                # Use glob for file extensions
                if list(self.repo_path.rglob(indicator)):
                    return True
        
        return False
    
    def _has_python_files(self) -> bool:
        """Check if repository contains Python files."""
        indicators = [
            "requirements.txt",
            "pyproject.toml",
            "setup.py",
            "*.py"
        ]
        
        for indicator in indicators:
            if indicator.endswith((".txt", ".toml", ".py")) and not indicator.startswith("*"):
                if (self.repo_path / indicator).exists():
                    return True
            else:
                # Use glob for file extensions
                if list(self.repo_path.rglob(indicator)):
                    return True
        
        return False
    
    def _run_semgrep(self) -> List[Dict[str, Any]]:
        """Run optional Semgrep analysis."""
        try:
            import subprocess
            import tempfile
            
            # Check if semgrep is available
            result = subprocess.run(["semgrep", "--version"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                if self.verbose:
                    console.print("   ⚠️  Semgrep not available - skipping static analysis", style="yellow")
                return []
            
            # Run semgrep with security rules
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name
            
            cmd = [
                "semgrep",
                "--config=auto",
                "--json",
                "--output", output_file,
                "--quiet",
                str(self.repo_path)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                with open(output_file, 'r') as f:
                    semgrep_data = json.load(f)
                
                # Convert semgrep results to our format
                findings = []
                for result in semgrep_data.get("results", []):
                    findings.append({
                        "type": "semgrep",
                        "rule_id": result.get("check_id", "unknown"),
                        "severity": result.get("extra", {}).get("severity", "info"),
                        "message": result.get("extra", {}).get("message", ""),
                        "file": result.get("path", ""),
                        "line": result.get("start", {}).get("line", 0),
                        "code": result.get("extra", {}).get("lines", "")
                    })
                
                # Cleanup
                Path(output_file).unlink(missing_ok=True)
                return findings
            
        except (ImportError, subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            if self.verbose:
                console.print(f"   ⚠️  Semgrep analysis failed: {e}", style="yellow")
        
        return []
    
    def _deduplicate_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate endpoints based on method and path."""
        seen = set()
        unique_endpoints = []
        
        for endpoint in endpoints:
            key = (endpoint.get("method", "").upper(), endpoint.get("path", ""))
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(endpoint)
        
        return unique_endpoints
