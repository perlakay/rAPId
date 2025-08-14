"""
GraphQL schema discovery and endpoint extraction.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from rich.console import Console

console = Console()

class GraphQLDiscovery:
    """Discovers GraphQL schemas and extracts operations."""
    
    def __init__(self, repo_path: Path, verbose: bool = False):
        self.repo_path = repo_path
        self.verbose = verbose
    
    def discover(self, explicit_endpoint: Optional[str] = None) -> Dict[str, Any]:
        """
        Discover GraphQL schemas and endpoints.
        
        Args:
            explicit_endpoint: Explicit GraphQL endpoint path
            
        Returns:
            Dictionary with discovered schemas and operations
        """
        results = {
            "schemas": [],
            "endpoints": [],
            "errors": []
        }
        
        # Search for GraphQL schema files
        schema_files = self._find_schema_files()
        
        for schema_file in schema_files:
            try:
                schema_content = self._parse_schema_file(schema_file)
                if schema_content:
                    operations = self._extract_operations(schema_content, schema_file)
                    
                    results["schemas"].append({
                        "file": str(schema_file),
                        "operations_count": len(operations)
                    })
                    
                    # Convert to endpoint format
                    for op in operations:
                        endpoint = {
                            "method": "POST",  # GraphQL typically uses POST
                            "path": explicit_endpoint or "/graphql",
                            "source": "graphql",
                            "source_file": str(schema_file),
                            "operation_type": op["type"],
                            "operation_name": op["name"],
                            "description": op.get("description", ""),
                            "parameters": op.get("args", []),
                            "auth_requirements": [],
                            "security_hints": self._analyze_operation_security(op)
                        }
                        results["endpoints"].append(endpoint)
                    
                    if self.verbose:
                        console.print(f"   📄 Parsed GraphQL schema: {len(operations)} operations")
                        
            except Exception as e:
                error_msg = f"Failed to parse GraphQL schema {schema_file}: {e}"
                results["errors"].append(error_msg)
                if self.verbose:
                    console.print(f"   ❌ {error_msg}", style="red")
        
        return results
    
    def _find_schema_files(self) -> List[Path]:
        """Find GraphQL schema files in the repository."""
        patterns = [
            "**/*.graphql",
            "**/*.gql",
            "**/schema.json",
            "**/introspection.json"
        ]
        
        schema_files = []
        for pattern in patterns:
            schema_files.extend(self.repo_path.glob(pattern))
        
        return list(set(f for f in schema_files if f.exists() and f.is_file()))
    
    def _parse_schema_file(self, schema_file: Path) -> Optional[str]:
        """Parse GraphQL schema file."""
        try:
            with open(schema_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Handle JSON introspection results
                if schema_file.suffix.lower() == '.json':
                    data = json.loads(content)
                    # Extract schema from introspection result
                    if 'data' in data and '__schema' in data['data']:
                        return self._introspection_to_sdl(data['data']['__schema'])
                    return None
                
                return content
        except Exception as e:
            if self.verbose:
                console.print(f"   ⚠️  Could not parse {schema_file}: {e}", style="yellow")
            return None
    
    def _extract_operations(self, schema_content: str, schema_file: Path) -> List[Dict[str, Any]]:
        """Extract GraphQL operations from schema content."""
        operations = []
        
        # Simple regex-based parsing for basic operation extraction
        # This is a simplified approach - a full GraphQL parser would be more robust
        
        # Find type definitions for Query, Mutation, Subscription
        type_patterns = [
            (r'type\s+Query\s*\{([^}]+)\}', 'query'),
            (r'type\s+Mutation\s*\{([^}]+)\}', 'mutation'),
            (r'type\s+Subscription\s*\{([^}]+)\}', 'subscription')
        ]
        
        for pattern, op_type in type_patterns:
            matches = re.finditer(pattern, schema_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                fields_content = match.group(1)
                fields = self._parse_fields(fields_content)
                
                for field in fields:
                    operations.append({
                        "type": op_type,
                        "name": field["name"],
                        "description": field.get("description", ""),
                        "args": field.get("args", []),
                        "return_type": field.get("return_type", "")
                    })
        
        return operations
    
    def _parse_fields(self, fields_content: str) -> List[Dict[str, Any]]:
        """Parse GraphQL fields from type definition content."""
        fields = []
        
        # Simple field parsing - matches field_name(args): ReturnType
        field_pattern = r'(\w+)\s*(?:\(([^)]*)\))?\s*:\s*([^\n]+)'
        
        for match in re.finditer(field_pattern, fields_content):
            field_name = match.group(1)
            args_str = match.group(2) or ""
            return_type = match.group(3).strip()
            
            # Parse arguments
            args = []
            if args_str:
                arg_pattern = r'(\w+)\s*:\s*([^,\n]+)'
                for arg_match in re.finditer(arg_pattern, args_str):
                    args.append({
                        "name": arg_match.group(1),
                        "type": arg_match.group(2).strip(),
                        "required": "!" in arg_match.group(2)
                    })
            
            fields.append({
                "name": field_name,
                "args": args,
                "return_type": return_type
            })
        
        return fields
    
    def _introspection_to_sdl(self, schema_data: Dict[str, Any]) -> str:
        """Convert GraphQL introspection result to SDL (simplified)."""
        # This is a very basic conversion - a full implementation would be more complex
        sdl_parts = []
        
        types = schema_data.get('types', [])
        for type_def in types:
            if type_def['name'].startswith('__'):
                continue  # Skip introspection types
            
            type_name = type_def['name']
            type_kind = type_def['kind']
            
            if type_kind == 'OBJECT' and type_name in ['Query', 'Mutation', 'Subscription']:
                fields = type_def.get('fields', [])
                field_strs = []
                
                for field in fields:
                    field_name = field['name']
                    field_type = self._type_to_string(field['type'])
                    field_strs.append(f"  {field_name}: {field_type}")
                
                sdl_parts.append(f"type {type_name} {{\n" + "\n".join(field_strs) + "\n}")
        
        return "\n\n".join(sdl_parts)
    
    def _type_to_string(self, type_def: Dict[str, Any]) -> str:
        """Convert GraphQL type definition to string representation."""
        if type_def['kind'] == 'NON_NULL':
            return self._type_to_string(type_def['ofType']) + '!'
        elif type_def['kind'] == 'LIST':
            return '[' + self._type_to_string(type_def['ofType']) + ']'
        else:
            return type_def.get('name', 'Unknown')
    
    def _analyze_operation_security(self, operation: Dict[str, Any]) -> List[str]:
        """Analyze GraphQL operation for security patterns."""
        hints = []
        
        op_name = operation["name"].lower()
        op_type = operation["type"]
        
        # Check for ID-like arguments
        for arg in operation.get("args", []):
            arg_name = arg["name"].lower()
            if any(id_hint in arg_name for id_hint in ["id", "uuid", "key"]):
                hints.append("has_id_param")
        
        # Check for mutating operations
        if op_type in ["mutation", "subscription"]:
            hints.append("mutating_operation")
        
        # Check for admin/sensitive operations
        sensitive_patterns = ["admin", "delete", "create", "update", "internal", "debug"]
        if any(pattern in op_name for pattern in sensitive_patterns):
            hints.append("sensitive_operation")
        
        return hints
