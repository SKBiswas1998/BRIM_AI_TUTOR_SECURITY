import requests
import json
import time
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional
import concurrent.futures
import urllib.parse

class FastAPISecurityTester:
    """Comprehensive security testing specifically for FastAPI applications"""
    
    def __init__(self, backend_url: str):
        self.backend_url = backend_url.rstrip('/')
        self.vulnerabilities = []
        self.session = requests.Session()
        
    def add_vulnerability(self, vuln_type: str, severity: str, endpoint: str, details: str, evidence: str):
        """Add vulnerability to findings"""
        self.vulnerabilities.append({
            "type": vuln_type,
            "severity": severity,
            "endpoint": endpoint,
            "details": details,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        })
    
    def test_fastapi_docs_exposure(self) -> None:
        """Test if FastAPI auto-documentation is exposed in production"""
        print("\n📚 Testing FastAPI Documentation Exposure...")
        
        doc_endpoints = [
            ("/docs", "Swagger UI"),
            ("/redoc", "ReDoc UI"),
            ("/openapi.json", "OpenAPI Schema"),
            ("/docs/oauth2-redirect", "OAuth2 Redirect"),
            ("/api/docs", "Alternative Docs Path"),
            ("/api/v1/docs", "Versioned Docs"),
            ("/swagger", "Alternative Swagger"),
            ("/api-docs", "Alternative API Docs")
        ]
        
        for endpoint, description in doc_endpoints:
            try:
                response = self.session.get(f"{self.backend_url}{endpoint}", timeout=5)
                
                if response.status_code == 200:
                    print(f"🚨 EXPOSED: {endpoint} ({description})")
                    
                    # Check if it's actually documentation
                    content = response.text.lower()
                    if any(keyword in content for keyword in ['swagger', 'openapi', 'redoc', 'api documentation']):
                        self.add_vulnerability(
                            vuln_type="API Documentation Exposure",
                            severity="HIGH",
                            endpoint=endpoint,
                            details=f"{description} is publicly accessible in production",
                            evidence=f"HTTP 200 response with API documentation content"
                        )
                        
                        # Extract sensitive information from docs
                        if endpoint == "/openapi.json":
                            try:
                                schema = response.json()
                                self._analyze_openapi_schema(schema)
                            except:
                                pass
                else:
                    print(f"✅ Protected: {endpoint}")
                    
            except Exception as e:
                print(f"❌ Error testing {endpoint}: {str(e)}")
    
    def _analyze_openapi_schema(self, schema: Dict[str, Any]) -> None:
        """Analyze OpenAPI schema for security issues"""
        print("🔍 Analyzing OpenAPI schema for security issues...")
        
        # Check for exposed sensitive paths
        paths = schema.get('paths', {})
        sensitive_paths = []
        
        for path, methods in paths.items():
            # Look for admin, internal, debug paths
            if any(keyword in path.lower() for keyword in ['admin', 'internal', 'debug', 'test', 'dev']):
                sensitive_paths.append(path)
            
            # Check for endpoints without security
            for method, details in methods.items():
                if 'security' not in details and 'admin' in path.lower():
                    self.add_vulnerability(
                        vuln_type="Unsecured Admin Endpoint",
                        severity="CRITICAL",
                        endpoint=path,
                        details=f"Admin endpoint {path} appears to lack security requirements",
                        evidence="No security schema defined in OpenAPI spec"
                    )
        
        if sensitive_paths:
            print(f"⚠️ Found sensitive paths: {sensitive_paths}")
        
        # Check for exposed server information
        servers = schema.get('servers', [])
        for server in servers:
            url = server.get('url', '')
            if 'localhost' in url or 'test' in url or 'dev' in url:
                self.add_vulnerability(
                    vuln_type="Development Server Exposure",
                    severity="MEDIUM",
                    endpoint="/openapi.json",
                    details=f"Development server URL exposed: {url}",
                    evidence="Development URLs in OpenAPI schema"
                )
    
    def test_parameter_pollution(self) -> None:
        """Test HTTP Parameter Pollution vulnerabilities"""
        print("\n🔄 Testing HTTP Parameter Pollution...")
        
        test_endpoints = [
            "/api/user",
            "/select/",
            "/quiz1/",
            "/subjects/"
        ]
        
        pollution_tests = [
            # Query parameter pollution
            ("id=1&id=2", "Duplicate query parameters"),
            ("id[]=1&id[]=2", "Array parameter pollution"),
            ("id=1&ID=2", "Case-sensitive pollution"),
            ("user_id=1&user-id=2&userId=3", "Similar parameter names"),
            
            # JSON parameter pollution  
            ('{"id": 1, "id": 2}', "Duplicate JSON keys"),
            ('{"user": {"id": 1}, "user": {"id": 2}}', "Nested duplicate keys"),
        ]
        
        for endpoint in test_endpoints:
            print(f"\nTesting parameter pollution on {endpoint}")
            
            for pollution_payload, description in pollution_tests:
                try:
                    if endpoint in ["/api/user", "/subjects/"]:
                        # GET request with query pollution
                        if not pollution_payload.startswith('{'):
                            url = f"{self.backend_url}{endpoint}?{pollution_payload}"
                            response = self.session.get(url, timeout=5)
                        else:
                            continue  # Skip JSON tests for GET endpoints
                    else:
                        # POST request with JSON pollution
                        if pollution_payload.startswith('{'):
                            try:
                                # This might fail due to duplicate keys, which is expected
                                data = json.loads(pollution_payload)
                                response = self.session.post(f"{self.backend_url}{endpoint}", json=data, timeout=5)
                            except json.JSONDecodeError:
                                # Try sending raw JSON string
                                headers = {'Content-Type': 'application/json'}
                                response = self.session.post(f"{self.backend_url}{endpoint}", 
                                                           data=pollution_payload, headers=headers, timeout=5)
                        else:
                            # Convert query params to JSON
                            params = urllib.parse.parse_qs(pollution_payload)
                            response = self.session.post(f"{self.backend_url}{endpoint}", json=params, timeout=5)
                    
                    # Check for unexpected behavior
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            # Look for signs that pollution was processed differently
                            if isinstance(data, dict) and any(isinstance(v, list) for v in data.values()):
                                print(f"⚠️ Potential parameter pollution: {description}")
                                print(f"  Response suggests array handling: {str(data)[:100]}...")
                        except:
                            pass
                    elif response.status_code == 422:
                        print(f"✅ Parameter validation blocks: {description}")
                    
                except Exception as e:
                    continue
    
    def test_fastapi_async_vulnerabilities(self) -> None:
        """Test for async-specific vulnerabilities in FastAPI"""
        print("\n⚡ Testing FastAPI Async Vulnerabilities...")
        
        # Test async endpoint flooding
        async_endpoints = ["/api/user", "/quiz1/", "/subjects/"]
        
        for endpoint in async_endpoints:
            print(f"Testing async flooding on {endpoint}")
            
            # Send many concurrent requests to test async handling
            def make_request():
                try:
                    return self.session.get(f"{self.backend_url}{endpoint}", timeout=1)
                except:
                    return None
            
            start_time = time.time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(make_request) for _ in range(100)]
                responses = [f.result() for f in concurrent.futures.as_completed(futures, timeout=10)]
            
            elapsed = time.time() - start_time
            successful = len([r for r in responses if r and r.status_code == 200])
            
            print(f"  Sent 100 requests in {elapsed:.2f}s, {successful} successful")
            
            # Check for DoS vulnerability
            if elapsed > 30:  # Took too long
                self.add_vulnerability(
                    vuln_type="Async DoS Vulnerability",
                    severity="HIGH",
                    endpoint=endpoint,
                    details=f"Endpoint vulnerable to async request flooding",
                    evidence=f"100 concurrent requests took {elapsed:.2f}s"
                )
                print(f"🚨 Potential DoS vulnerability detected")
    
    def test_pydantic_model_vulnerabilities(self) -> None:
        """Test for Pydantic model-related vulnerabilities"""
        print("\n🏗️ Testing Pydantic Model Vulnerabilities...")
        
        # Test model injection attacks
        model_injection_payloads = [
            # Field injection
            {"__class__": {"__module__": "os", "__name__": "system"}},
            {"__dict__": {"admin": True}},
            {"__init__": {"role": "admin"}},
            
            # Pydantic-specific
            {"__fields__": {"admin": True}},
            {"__config__": {"allow_mutation": True}},
            {"__validators__": {}},
            
            # Mass assignment
            {"id": 1, "role": "admin", "permissions": ["all"]},
            {"user_id": 1, "is_admin": True, "verified": True},
        ]
        
        test_endpoints = ["/quiz1/", "/select/", "/api/user"]
        
        for endpoint in test_endpoints:
            for payload in model_injection_payloads:
                try:
                    response = self.session.post(f"{self.backend_url}{endpoint}", json=payload, timeout=5)
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            # Check if malicious fields were accepted
                            if any(key in str(data).lower() for key in ['admin', 'role', 'permission']):
                                self.add_vulnerability(
                                    vuln_type="Pydantic Model Injection",
                                    severity="HIGH",
                                    endpoint=endpoint,
                                    details="Pydantic model accepts dangerous field injection",
                                    evidence=f"Payload accepted: {payload}"
                                )
                                print(f"🚨 Model injection successful at {endpoint}")
                                break
                        except:
                            pass
                            
                except Exception as e:
                    continue
    
    def test_fastapi_dependency_injection(self) -> None:
        """Test FastAPI dependency injection vulnerabilities"""
        print("\n💉 Testing FastAPI Dependency Injection...")
        
        # Test dependency bypass through headers
        dependency_bypass_headers = [
            {"X-User-ID": "1"},
            {"X-Current-User": "admin"},
            {"X-Authenticated": "true"},
            {"X-Skip-Auth": "true"},
            {"X-Internal": "true"},
            {"X-Debug": "true"},
            {"Authorization": "Internal-Service"},
            {"X-Service-Token": "internal"},
        ]
        
        protected_endpoints = ["/api/user", "/dashboard/math/algebra/", "/api/admin"]
        
        for endpoint in protected_endpoints:
            print(f"Testing dependency bypass on {endpoint}")
            
            # First, test without any headers
            baseline = self.session.get(f"{self.backend_url}{endpoint}", timeout=5)
            baseline_status = baseline.status_code if baseline else 500
            
            for headers in dependency_bypass_headers:
                try:
                    response = self.session.get(f"{self.backend_url}{endpoint}", headers=headers, timeout=5)
                    
                    if response and response.status_code == 200 and baseline_status != 200:
                        self.add_vulnerability(
                            vuln_type="Dependency Injection Bypass",
                            severity="CRITICAL",
                            endpoint=endpoint,
                            details=f"Dependency injection bypassed with headers: {headers}",
                            evidence=f"Baseline: {baseline_status}, With headers: {response.status_code}"
                        )
                        print(f"🚨 Dependency bypass successful: {headers}")
                        break
                        
                except Exception as e:
                    continue
    
    def test_fastapi_middleware_vulnerabilities(self) -> None:
        """Test FastAPI middleware-related vulnerabilities"""
        print("\n🔄 Testing FastAPI Middleware Vulnerabilities...")
        
        # Test CORS middleware bypass
        cors_bypass_headers = [
            {"Origin": "https://evil.com"},
            {"Origin": "null"},
            {"Origin": "file://"},
            {"Origin": f"{self.backend_url}.evil.com"},
            {"Origin": f"https://{self.backend_url[8:]}.evil.com"},  # Remove https://
        ]
        
        for headers in cors_bypass_headers:
            try:
                response = self.session.options(f"{self.backend_url}/api/user", headers=headers, timeout=5)
                
                if response:
                    cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                    if cors_header == "*" or headers["Origin"] in cors_header:
                        self.add_vulnerability(
                            vuln_type="CORS Middleware Bypass",
                            severity="HIGH",
                            endpoint="/api/user",
                            details=f"CORS allows unauthorized origin: {headers['Origin']}",
                            evidence=f"Access-Control-Allow-Origin: {cors_header}"
                        )
                        print(f"🚨 CORS bypass: {headers['Origin']}")
                        
            except Exception as e:
                continue
        
        # Test middleware order vulnerabilities
        print("Testing middleware order issues...")
        
        # Send malformed requests to test middleware handling
        malformed_tests = [
            {"data": "not-json", "content_type": "application/json"},
            {"data": '{"unclosed": "json"', "content_type": "application/json"},
            {"data": "A" * 10000, "content_type": "application/json"},  # Large payload
            {"data": '{"deeply": {"nested": {"object": {"that": {"goes": {"very": {"deep": {}}}}}}}', "content_type": "application/json"},
        ]
        
        for test in malformed_tests:
            try:
                headers = {"Content-Type": test["content_type"]}
                response = self.session.post(f"{self.backend_url}/quiz1/", 
                                           data=test["data"], headers=headers, timeout=5)
                
                # Check for stack traces or detailed errors
                if response and "traceback" in response.text.lower():
                    self.add_vulnerability(
                        vuln_type="Middleware Error Exposure",
                        severity="MEDIUM",
                        endpoint="/quiz1/",
                        details="Middleware exposes detailed error information",
                        evidence="Stack trace visible in error response"
                    )
                    print(f"⚠️ Error information exposed")
                    
            except Exception as e:
                continue
    
    def run_comprehensive_fastapi_test(self) -> Dict[str, Any]:
        """Run all FastAPI-specific security tests"""
        print("="*60)
        print("🔒 FASTAPI-SPECIFIC SECURITY TESTING")
        print("="*60)
        print(f"Target: {self.backend_url}")
        
        start_time = time.time()
        
        # Run all test categories
        self.test_fastapi_docs_exposure()
        self.test_parameter_pollution()
        self.test_fastapi_async_vulnerabilities()
        self.test_pydantic_model_vulnerabilities()
        self.test_fastapi_dependency_injection()
        self.test_fastapi_middleware_vulnerabilities()
        
        elapsed_time = time.time() - start_time
        
        # Generate report
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln["severity"]] += 1
        
        report = {
            "target": self.backend_url,
            "test_duration": elapsed_time,
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
            "vulnerabilities": self.vulnerabilities,
            "test_categories": [
                "FastAPI Documentation Exposure",
                "HTTP Parameter Pollution",
                "Async Vulnerabilities",
                "Pydantic Model Injection",
                "Dependency Injection Bypass",
                "Middleware Vulnerabilities"
            ]
        }
        
        # Print summary
        print("\n" + "="*60)
        print("📊 FASTAPI SECURITY REPORT")
        print("="*60)
        print(f"Test Duration: {elapsed_time:.2f} seconds")
        print(f"Total Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Critical: {severity_counts['CRITICAL']}")
        print(f"High: {severity_counts['HIGH']}")
        print(f"Medium: {severity_counts['MEDIUM']}")
        print(f"Low: {severity_counts['LOW']}")
        
        if self.vulnerabilities:
            print("\n🚨 VULNERABILITIES FOUND:")
            for vuln in self.vulnerabilities:
                print(f"  {vuln['severity']}: {vuln['type']} at {vuln['endpoint']}")
                print(f"    → {vuln['details']}")
        else:
            print("\n✅ No FastAPI-specific vulnerabilities found!")
        
        return report

# Usage
if __name__ == "__main__":
    # Test BrimAI backend
    backend_url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app"
    
    tester = FastAPISecurityTester(backend_url)
    results = tester.run_comprehensive_fastapi_test()
    
    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    with open(f"fastapi_security_report_{timestamp}.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Report saved to: fastapi_security_report_{timestamp}.json")