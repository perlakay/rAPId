"""
SQLite database for storing endpoint and security data.
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional
from rich.console import Console

console = Console()

class SecurityDatabase:
    """SQLite database for storing security analysis data."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS endpoints (
                    id TEXT PRIMARY KEY,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    path_template TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_file TEXT,
                    parameters TEXT,  -- JSON
                    id_parameters TEXT,  -- JSON
                    auth_requirements TEXT,  -- JSON
                    auth_detected BOOLEAN,
                    security_hints TEXT,  -- JSON
                    metadata TEXT,  -- JSON
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS test_results (
                    id TEXT PRIMARY KEY,
                    endpoint_id TEXT,
                    test_type TEXT NOT NULL,
                    test_name TEXT NOT NULL,
                    status TEXT NOT NULL,  -- vulnerable, secure, inconclusive, error
                    severity TEXT,  -- high, medium, low
                    evidence TEXT,  -- JSON
                    request_data TEXT,  -- JSON
                    response_data TEXT,  -- JSON
                    timing_ms INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints (id)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    file_path TEXT,
                    line_number INTEGER,
                    pattern TEXT,
                    metadata TEXT,  -- JSON
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for better query performance
            conn.execute('CREATE INDEX IF NOT EXISTS idx_endpoints_method_path ON endpoints (method, path_template)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_test_results_endpoint ON test_results (endpoint_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_test_results_status ON test_results (status)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_security_findings_severity ON security_findings (severity)')
    
    def store_endpoints(self, endpoints: List[Dict[str, Any]]) -> None:
        """Store normalized endpoints in the database."""
        with sqlite3.connect(self.db_path) as conn:
            for endpoint in endpoints:
                conn.execute('''
                    INSERT OR REPLACE INTO endpoints (
                        id, method, path, path_template, source, source_file,
                        parameters, id_parameters, auth_requirements, auth_detected,
                        security_hints, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    endpoint.get('id'),
                    endpoint.get('method'),
                    endpoint.get('path'),
                    endpoint.get('path_template'),
                    endpoint.get('source'),
                    endpoint.get('source_file'),
                    json.dumps(endpoint.get('parameters', [])),
                    json.dumps(endpoint.get('id_parameters', [])),
                    json.dumps(endpoint.get('auth_requirements', [])),
                    endpoint.get('auth_detected', False),
                    json.dumps(endpoint.get('security_hints', [])),
                    json.dumps(endpoint.get('metadata', {}))
                ))
            
            conn.commit()
    
    def store_test_results(self, results: List[Dict[str, Any]]) -> None:
        """Store test results in the database."""
        with sqlite3.connect(self.db_path) as conn:
            for result in results:
                conn.execute('''
                    INSERT INTO test_results (
                        id, endpoint_id, test_type, test_name, status, severity,
                        evidence, request_data, response_data, timing_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result.get('id'),
                    result.get('endpoint_id'),
                    result.get('test_type'),
                    result.get('test_name'),
                    result.get('status'),
                    result.get('severity'),
                    json.dumps(result.get('evidence', {})),
                    json.dumps(result.get('request_data', {})),
                    json.dumps(result.get('response_data', {})),
                    result.get('timing_ms')
                ))
            
            conn.commit()
    
    def store_security_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Store static security findings in the database."""
        with sqlite3.connect(self.db_path) as conn:
            for finding in findings:
                conn.execute('''
                    INSERT INTO security_findings (
                        type, severity, message, file_path, line_number, pattern, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    finding.get('type'),
                    finding.get('severity'),
                    finding.get('message'),
                    finding.get('file_path'),
                    finding.get('line_number'),
                    finding.get('pattern'),
                    json.dumps(finding.get('metadata', {}))
                ))
            
            conn.commit()
    
    def get_endpoints(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Retrieve endpoints with optional filters."""
        query = 'SELECT * FROM endpoints'
        params = []
        
        if filters:
            conditions = []
            if 'method' in filters:
                conditions.append('method = ?')
                params.append(filters['method'])
            if 'source' in filters:
                conditions.append('source = ?')
                params.append(filters['source'])
            if 'has_auth' in filters:
                conditions.append('auth_detected = ?')
                params.append(filters['has_auth'])
            
            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY method, path_template'
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            
            endpoints = []
            for row in cursor.fetchall():
                endpoint = dict(row)
                # Parse JSON fields
                endpoint['parameters'] = json.loads(endpoint['parameters'] or '[]')
                endpoint['id_parameters'] = json.loads(endpoint['id_parameters'] or '[]')
                endpoint['auth_requirements'] = json.loads(endpoint['auth_requirements'] or '[]')
                endpoint['security_hints'] = json.loads(endpoint['security_hints'] or '[]')
                endpoint['metadata'] = json.loads(endpoint['metadata'] or '{}')
                endpoints.append(endpoint)
            
            return endpoints
    
    def get_test_results(self, endpoint_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve test results, optionally filtered by endpoint."""
        query = 'SELECT * FROM test_results'
        params = []
        
        if endpoint_id:
            query += ' WHERE endpoint_id = ?'
            params.append(endpoint_id)
        
        query += ' ORDER BY created_at DESC'
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                # Parse JSON fields
                result['evidence'] = json.loads(result['evidence'] or '{}')
                result['request_data'] = json.loads(result['request_data'] or '{}')
                result['response_data'] = json.loads(result['response_data'] or '{}')
                results.append(result)
            
            return results
    
    def get_security_findings(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve security findings, optionally filtered by severity."""
        query = 'SELECT * FROM security_findings'
        params = []
        
        if severity:
            query += ' WHERE severity = ?'
            params.append(severity)
        
        query += ' ORDER BY severity DESC, created_at DESC'
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            
            findings = []
            for row in cursor.fetchall():
                finding = dict(row)
                finding['metadata'] = json.loads(finding['metadata'] or '{}')
                findings.append(finding)
            
            return findings
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics from the database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Endpoint stats
            endpoint_stats = conn.execute('''
                SELECT 
                    COUNT(*) as total_endpoints,
                    COUNT(CASE WHEN auth_detected = 1 THEN 1 END) as authenticated_endpoints,
                    COUNT(CASE WHEN auth_detected = 0 THEN 1 END) as unauthenticated_endpoints
                FROM endpoints
            ''').fetchone()
            
            # Method distribution
            method_stats = conn.execute('''
                SELECT method, COUNT(*) as count
                FROM endpoints
                GROUP BY method
                ORDER BY count DESC
            ''').fetchall()
            
            # Source distribution
            source_stats = conn.execute('''
                SELECT source, COUNT(*) as count
                FROM endpoints
                GROUP BY source
                ORDER BY count DESC
            ''').fetchall()
            
            # Test result stats
            test_stats = conn.execute('''
                SELECT 
                    COUNT(*) as total_tests,
                    COUNT(CASE WHEN status = 'vulnerable' THEN 1 END) as vulnerable,
                    COUNT(CASE WHEN status = 'secure' THEN 1 END) as secure,
                    COUNT(CASE WHEN status = 'inconclusive' THEN 1 END) as inconclusive,
                    COUNT(CASE WHEN status = 'error' THEN 1 END) as errors
                FROM test_results
            ''').fetchone()
            
            # Severity distribution
            severity_stats = conn.execute('''
                SELECT severity, COUNT(*) as count
                FROM test_results
                WHERE status = 'vulnerable'
                GROUP BY severity
                ORDER BY 
                    CASE severity 
                        WHEN 'high' THEN 1 
                        WHEN 'medium' THEN 2 
                        WHEN 'low' THEN 3 
                        ELSE 4 
                    END
            ''').fetchall()
            
            # Security findings stats
            findings_stats = conn.execute('''
                SELECT 
                    COUNT(*) as total_findings,
                    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_severity,
                    COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium_severity,
                    COUNT(CASE WHEN severity = 'low' THEN 1 END) as low_severity
                FROM security_findings
            ''').fetchone()
            
            return {
                'endpoints': dict(endpoint_stats) if endpoint_stats else {},
                'methods': [dict(row) for row in method_stats],
                'sources': [dict(row) for row in source_stats],
                'tests': dict(test_stats) if test_stats else {},
                'severity': [dict(row) for row in severity_stats],
                'findings': dict(findings_stats) if findings_stats else {}
            }
    
    def get_vulnerable_endpoints(self) -> List[Dict[str, Any]]:
        """Get endpoints with vulnerable test results."""
        query = '''
            SELECT DISTINCT e.*, tr.test_type, tr.test_name, tr.severity, tr.evidence
            FROM endpoints e
            JOIN test_results tr ON e.id = tr.endpoint_id
            WHERE tr.status = 'vulnerable'
            ORDER BY 
                CASE tr.severity 
                    WHEN 'high' THEN 1 
                    WHEN 'medium' THEN 2 
                    WHEN 'low' THEN 3 
                    ELSE 4 
                END,
                e.method, e.path_template
        '''
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query)
            
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                # Parse JSON fields
                result['parameters'] = json.loads(result['parameters'] or '[]')
                result['id_parameters'] = json.loads(result['id_parameters'] or '[]')
                result['auth_requirements'] = json.loads(result['auth_requirements'] or '[]')
                result['security_hints'] = json.loads(result['security_hints'] or '[]')
                result['metadata'] = json.loads(result['metadata'] or '{}')
                result['evidence'] = json.loads(result['evidence'] or '{}')
                results.append(result)
            
            return results
