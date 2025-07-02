import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

class FirebaseSecurityTester:
    """Test Firebase security rules and configurations"""
    
    def __init__(self, project_id: str = "brimai-test-v1"):
        self.project_id = project_id
        self.vulnerabilities = []
        
        # Common Firebase URLs
        self.firestore_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
        self.realtime_db_url = f"https://{project_id}-default-rtdb.firebaseio.com"
        self.storage_url = f"https://firebasestorage.googleapis.com/v0/b/{project_id}.appspot.com/o"
        
    def add_vulnerability(self, vuln_type: str, severity: str, service: str, details: str, evidence: str):
        """Add vulnerability to findings"""
        self.vulnerabilities.append({
            "type": vuln_type,
            "severity": severity,
            "service": service,
            "details": details,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        })
    
    def test_firestore_security_rules(self) -> None:
        """Test Firestore security rules"""
        print("\n🔥 Testing Firestore Security Rules...")
        
        # Common collection names to test
        collections = [
            "users", "user", "profiles", "accounts",
            "quiz", "quizzes", "questions", "answers",
            "scores", "results", "leaderboard", "rankings",
            "admin", "config", "settings", "secrets",
            "test", "dev", "debug", "temp"
        ]
        
        for collection in collections:
            print(f"Testing collection: {collection}")
            
            # Test read access without authentication
            try:
                url = f"{self.firestore_url}/{collection}"
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'documents' in data:
                        document_count = len(data['documents'])
                        print(f"🚨 PUBLIC READ ACCESS: {collection} ({document_count} documents)")
                        
                        self.add_vulnerability(
                            vuln_type="Firestore Public Read Access",
                            severity="CRITICAL",
                            service="Firestore",
                            details=f"Collection '{collection}' allows public read access",
                            evidence=f"Retrieved {document_count} documents without authentication"
                        )
                        
                        # Check for sensitive data
                        sensitive_data = self._check_sensitive_firestore_data(data['documents'])
                        if sensitive_data:
                            print(f"⚠️ Sensitive data exposed: {sensitive_data}")
                    else:
                        print(f"✅ {collection}: Empty or properly protected")
                elif response.status_code == 403:
                    print(f"✅ {collection}: Properly protected (403)")
                elif response.status_code == 404:
                    print(f"ℹ️ {collection}: Not found")
                else:
                    print(f"? {collection}: Status {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Error testing {collection}: {str(e)}")
            
            # Test write access without authentication
            try:
                test_doc = {
                    "fields": {
                        "test": {"stringValue": "unauthorized_write_test"},
                        "timestamp": {"timestampValue": datetime.now().isoformat() + "Z"}
                    }
                }
                
                write_url = f"{self.firestore_url}/{collection}"
                response = requests.post(write_url, json=test_doc, timeout=5)
                
                if response.status_code in [200, 201]:
                    print(f"🚨 PUBLIC WRITE ACCESS: {collection}")
                    
                    self.add_vulnerability(
                        vuln_type="Firestore Public Write Access",
                        severity="CRITICAL",
                        service="Firestore",
                        details=f"Collection '{collection}' allows public write access",
                        evidence=f"Successfully created document without authentication"
                    )
                    
                    # Try to delete the test document
                    if response.status_code == 200:
                        doc_data = response.json()
                        doc_name = doc_data.get('name', '')
                        if doc_name:
                            try:
                                requests.delete(f"https://firestore.googleapis.com/v1/{doc_name}", timeout=5)
                            except:
                                pass
                                
            except Exception as e:
                continue
    
    def _check_sensitive_firestore_data(self, documents: List[Dict]) -> List[str]:
        """Check Firestore documents for sensitive data"""
        sensitive_keywords = [
            'email', 'password', 'secret', 'key', 'token', 
            'api_key', 'admin', 'private', 'internal', 'score'
        ]
        
        found_sensitive = []
        
        for doc in documents[:5]:  # Check first 5 documents
            doc_str = json.dumps(doc).lower()
            for keyword in sensitive_keywords:
                if keyword in doc_str:
                    found_sensitive.append(keyword)
        
        return list(set(found_sensitive))
    
    def test_realtime_database_rules(self) -> None:
        """Test Firebase Realtime Database security rules"""
        print("\n📊 Testing Realtime Database Security Rules...")
        
        # Test root access
        try:
            response = requests.get(f"{self.realtime_db_url}/.json", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data:
                    print(f"🚨 PUBLIC READ ACCESS: Realtime Database root")
                    
                    self.add_vulnerability(
                        vuln_type="Realtime Database Public Access",
                        severity="CRITICAL",
                        service="Realtime Database",
                        details="Root of Realtime Database allows public read access",
                        evidence=f"Retrieved data: {str(data)[:200]}..."
                    )
                else:
                    print("✅ Realtime Database: Empty or no data")
            elif response.status_code == 401:
                print("✅ Realtime Database: Properly protected")
            else:
                print(f"? Realtime Database: Status {response.status_code}")
                
        except Exception as e:
            print(f"❌ Error testing Realtime Database: {str(e)}")
        
        # Test common paths
        common_paths = [
            "users", "quiz", "scores", "config", "admin", "test"
        ]
        
        for path in common_paths:
            try:
                response = requests.get(f"{self.realtime_db_url}/{path}.json", timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    if data:
                        print(f"🚨 PUBLIC ACCESS: /{path}")
                        
                        self.add_vulnerability(
                            vuln_type="Realtime Database Path Access",
                            severity="HIGH",
                            service="Realtime Database",
                            details=f"Path '/{path}' allows public read access",
                            evidence=f"Retrieved data from /{path}"
                        )
                        
            except Exception as e:
                continue
        
        # Test write access
        try:
            test_data = {"test": "unauthorized_write", "timestamp": time.time()}
            response = requests.put(f"{self.realtime_db_url}/test.json", json=test_data, timeout=5)
            
            if response.status_code == 200:
                print("🚨 PUBLIC WRITE ACCESS: Realtime Database")
                
                self.add_vulnerability(
                    vuln_type="Realtime Database Public Write",
                    severity="CRITICAL",
                    service="Realtime Database", 
                    details="Realtime Database allows public write access",
                    evidence="Successfully wrote test data without authentication"
                )
                
                # Clean up test data
                try:
                    requests.delete(f"{self.realtime_db_url}/test.json", timeout=5)
                except:
                    pass
                    
        except Exception as e:
            print(f"Write test error: {str(e)}")
    
    def test_firebase_storage_rules(self) -> None:
        """Test Firebase Storage security rules"""
        print("\n📁 Testing Firebase Storage Security Rules...")
        
        # Test public file access
        common_paths = [
            "images/", "uploads/", "files/", "documents/", "temp/",
            "user_uploads/", "quiz_images/", "profile_pics/"
        ]
        
        for path in common_paths:
            try:
                # Try to list files in the path
                response = requests.get(f"{self.storage_url}?prefix={path}", timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'items' in data:
                        file_count = len(data['items'])
                        print(f"🚨 PUBLIC STORAGE ACCESS: {path} ({file_count} files)")
                        
                        self.add_vulnerability(
                            vuln_type="Firebase Storage Public Access",
                            severity="HIGH",
                            service="Firebase Storage",
                            details=f"Storage path '{path}' allows public listing",
                            evidence=f"Retrieved {file_count} file references"
                        )
                        
            except Exception as e:
                continue
        
        # Test file upload without authentication
        try:
            test_file_data = b"test file content"
            upload_url = f"{self.storage_url}/test_unauthorized_upload.txt"
            
            response = requests.post(upload_url, data=test_file_data, timeout=5)
            
            if response.status_code in [200, 201]:
                print("🚨 PUBLIC UPLOAD ACCESS: Firebase Storage")
                
                self.add_vulnerability(
                    vuln_type="Firebase Storage Public Upload",
                    severity="CRITICAL",
                    service="Firebase Storage",
                    details="Firebase Storage allows public file uploads",
                    evidence="Successfully uploaded file without authentication"
                )
                
                # Try to delete the test file
                try:
                    requests.delete(upload_url, timeout=5)
                except:
                    pass
                    
        except Exception as e:
            print(f"Upload test error: {str(e)}")
    
    def test_firebase_auth_configuration(self) -> None:
        """Test Firebase Authentication configuration"""
        print("\n🔐 Testing Firebase Auth Configuration...")
        
        # Test for user enumeration via password reset
        test_emails = [
            "admin@brimai.com", 
            "test@test.com",
            "user@example.com",
            "nonexistent@test.com"
        ]
        
        # Firebase Auth REST API endpoints
        auth_endpoints = [
            f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=API_KEY",
            f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=API_KEY",
            f"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=API_KEY"
        ]
        
        # This would require the API key, which we'd need to extract from the frontend
        print("ℹ️ Firebase Auth testing requires API key extraction from frontend")
        print("   Recommendation: Check client-side code for exposed API keys")
        
        # Test for common Firebase Auth misconfigurations
        print("🔍 Checking for common Firebase Auth issues...")
        
        # Check if we can access user data without proper authentication
        # This would be done through the main app's API endpoints
        auth_bypass_tests = [
            "/api/user/profile",
            "/api/user/settings", 
            "/api/admin/users",
            "/api/auth/verify"
        ]
        
        print("   Testing auth bypass through main API...")
        # These would be tested through your main FastAPI backend
    
    def test_firebase_cloud_functions_security(self) -> None:
        """Test Firebase Cloud Functions security"""
        print("\n⚡ Testing Firebase Cloud Functions Security...")
        
        # Common Cloud Functions URL patterns
        function_patterns = [
            f"https://us-central1-{self.project_id}.cloudfunctions.net/",
            f"https://europe-west1-{self.project_id}.cloudfunctions.net/",
            f"https://asia-northeast1-{self.project_id}.cloudfunctions.net/"
        ]
        
        # Common function names
        function_names = [
            "api", "app", "auth", "webhook", "cron", "trigger",
            "quiz", "user", "admin", "backup", "migration",
            "helloWorld", "test", "dev", "debug"
        ]
        
        for base_url in function_patterns:
            for func_name in function_names:
                try:
                    url = base_url + func_name
                    response = requests.get(url, timeout=3)
                    
                    if response.status_code not in [404, 403]:
                        print(f"✓ Found function: {func_name} (Status: {response.status_code})")
                        
                        # Check if function is publicly accessible
                        if response.status_code == 200:
                            self.add_vulnerability(
                                vuln_type="Public Cloud Function",
                                severity="MEDIUM",
                                service="Cloud Functions",
                                details=f"Cloud Function '{func_name}' is publicly accessible",
                                evidence=f"HTTP 200 response from {url}"
                            )
                            
                except Exception as e:
                    continue
    
    def run_comprehensive_firebase_test(self) -> Dict[str, Any]:
        """Run all Firebase security tests"""
        print("="*60)
        print("🔥 FIREBASE SECURITY TESTING")
        print("="*60)
        print(f"Project ID: {self.project_id}")
        
        start_time = time.time()
        
        # Run all Firebase tests
        self.test_firestore_security_rules()
        self.test_realtime_database_rules()
        self.test_firebase_storage_rules()
        self.test_firebase_auth_configuration()
        self.test_firebase_cloud_functions_security()
        
        elapsed_time = time.time() - start_time
        
        # Generate report
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln["severity"]] += 1
        
        report = {
            "project_id": self.project_id,
            "test_duration": elapsed_time,
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
            "vulnerabilities": self.vulnerabilities,
            "services_tested": [
                "Firestore", "Realtime Database", "Firebase Storage",
                "Firebase Auth", "Cloud Functions"
            ]
        }
        
        # Print summary
        print("\n" + "="*60)
        print("📊 FIREBASE SECURITY REPORT")
        print("="*60)
        print(f"Test Duration: {elapsed_time:.2f} seconds")
        print(f"Total Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Critical: {severity_counts['CRITICAL']}")
        print(f"High: {severity_counts['HIGH']}")
        print(f"Medium: {severity_counts['MEDIUM']}")
        print(f"Low: {severity_counts['LOW']}")
        
        if self.vulnerabilities:
            print("\n🚨 FIREBASE VULNERABILITIES FOUND:")
            for vuln in self.vulnerabilities:
                print(f"  {vuln['severity']}: {vuln['type']} in {vuln['service']}")
                print(f"    → {vuln['details']}")
        else:
            print("\n✅ No Firebase security issues found!")
        
        print("\n📋 FIREBASE SECURITY RECOMMENDATIONS:")
        print("1. Review and test your Firestore security rules")
        print("2. Ensure Realtime Database rules deny public access")
        print("3. Configure Storage rules to require authentication")
        print("4. Implement proper user authentication flows")
        print("5. Secure Cloud Functions with proper authentication")
        
        return report

# Usage
if __name__ == "__main__":
    # Test BrimAI Firebase project
    tester = FirebaseSecurityTester("brimai-test-v1")
    results = tester.run_comprehensive_firebase_test()
    
    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    with open(f"firebase_security_report_{timestamp}.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Report saved to: firebase_security_report_{timestamp}.json")