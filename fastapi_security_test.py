import requests
import json
import jwt
import base64
from datetime import datetime

print("="*60)
print("BrimAI FastAPI Backend Security Test")
print("="*60)

# Your actual backend URL
backend_url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app"

print(f"\nBackend URL: {backend_url}")
print("\n[1] Testing API Endpoints...")
print("-"*60)

# Common FastAPI endpoints
endpoints = [
    ("GET", "/", None),
    ("GET", "/docs", None),
    ("GET", "/redoc", None),
    ("GET", "/openapi.json", None),
    ("GET", "/api", None),
    ("GET", "/api/v1", None),
    ("GET", "/health", None),
    ("GET", "/api/health", None),
    
    # Auth endpoints
    ("GET", "/auth/google", None),
    ("POST", "/auth/login", {"email": "test@test.com", "password": "test"}),
    ("POST", "/auth/register", {"email": "test@test.com", "password": "test"}),
    ("GET", "/auth/me", None),
    
    # API endpoints from your app
    ("GET", "/api/user", None),
    ("GET", "/api/quiz", None),
    ("GET", "/api/quiz/questions", None),
    ("GET", "/api/quiz/results", None),
    ("GET", "/api/dashboard", None),
    ("GET", "/api/profile", None),
    ("GET", "/api/leaderboard", None),
    
    # Common FastAPI patterns
    ("GET", "/users", None),
    ("GET", "/items", None),
    ("GET", "/api/users", None),
    ("GET", "/api/items", None)
]

api_discovered = []

for method, endpoint, data in endpoints:
    try:
        url = backend_url + endpoint
        
        if method == "GET":
            response = requests.get(url, timeout=5)
        else:
            response = requests.post(url, json=data, timeout=5)
            
        if response.status_code != 404:
            print(f"{method} {endpoint}: {response.status_code}")
            api_discovered.append((method, endpoint, response.status_code))
            
            # Special handling for OpenAPI
            if endpoint == "/openapi.json" and response.status_code == 200:
                print("   OpenAPI documentation found!")
                try:
                    api_spec = response.json()
                    print(f"  API Title: {api_spec.get('info', {}).get('title', 'Unknown')}")
                    print(f"  Version: {api_spec.get('info', {}).get('version', 'Unknown')}")
                    
                    # Extract all paths
                    if 'paths' in api_spec:
                        print(f"  Found {len(api_spec['paths'])} endpoints:")
                        for path in list(api_spec['paths'].keys())[:10]:
                            print(f"    - {path}")
                except:
                    pass
                    
    except requests.exceptions.Timeout:
        print(f"{method} {endpoint}: Timeout")
    except Exception as e:
        if "Connection" not in str(e):
            print(f"{method} {endpoint}: {type(e).__name__}")

# Test the JWT from OAuth state
print("\n[2] Analyzing JWT Token...")
print("-"*60)

jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTE0MzYxMTksIm5vbmNlIjoiNDE1NTAzZDBjOWYyZGMxYiJ9.SR0smx8oYytKi6FA2lve24LZOO1DbTTJxzzLwNu9cXc"

try:
    # Decode without verification
    header = jwt.get_unverified_header(jwt_token)
    payload = jwt.decode(jwt_token, options={"verify_signature": False})
    
    print(f"JWT Header: {header}")
    print(f"JWT Payload: {payload}")
    
    # Check expiration
    if 'exp' in payload:
        exp_time = datetime.fromtimestamp(payload['exp'])
        print(f"Token expires at: {exp_time}")
        
except Exception as e:
    print(f"JWT decode error: {e}")

# Test for common vulnerabilities
print("\n[3] Testing Common API Vulnerabilities...")
print("-"*60)

# SQL Injection tests
sql_payloads = ["'", "' OR '1'='1", "'; DROP TABLE users;--", "1' UNION SELECT * FROM users--"]
for payload in sql_payloads:
    try:
        response = requests.get(f"{backend_url}/api/user?id={payload}", timeout=5)
        if "error" in response.text.lower() or "sql" in response.text.lower():
            print(f"  Potential SQL injection with payload: {payload}")
    except:
        pass

# Test authentication bypass
print("\n[4] Testing Authentication Bypass...")
print("-"*60)

bypass_headers = [
    {"Authorization": "Bearer fake-token"},
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer "},
    {"X-API-Key": "admin"},
    {"X-User-ID": "1"},
    {"X-Admin": "true"}
]

protected_endpoints = ["/api/user", "/api/dashboard", "/api/quiz/results", "/api/profile"]

for endpoint in protected_endpoints:
    for headers in bypass_headers:
        try:
            response = requests.get(backend_url + endpoint, headers=headers, timeout=5)
            if response.status_code == 200:
                print(f" VULNERABLE: {endpoint} accepts {headers}")
                break
            elif response.status_code == 401:
                print(f" Protected: {endpoint}")
                break
        except:
            pass

# CORS test
print("\n[5] Testing CORS Configuration...")
print("-"*60)

cors_origins = [
    "https://evil.com",
    "http://localhost:3000",
    "null"
]

for origin in cors_origins:
    try:
        headers = {"Origin": origin}
        response = requests.options(f"{backend_url}/api/user", headers=headers, timeout=5)
        
        if "access-control-allow-origin" in response.headers:
            allowed_origin = response.headers["access-control-allow-origin"]
            if allowed_origin == "*" or allowed_origin == origin:
                print(f"  CORS allows origin: {origin}")
        else:
            print(f" CORS blocks origin: {origin}")
    except:
        pass

# Summary
print("\n" + "="*60)
print("SECURITY ASSESSMENT SUMMARY")
print("="*60)

if api_discovered:
    print(f"\n Found {len(api_discovered)} API endpoints")
    print("\nAccessible endpoints:")
    for method, endpoint, status in api_discovered:
        if status in [200, 405, 422]:
            print(f"  - {method} {endpoint} ({status})")

print("\nNEXT STEPS:")
print("1. Check /docs or /openapi.json for full API documentation")
print("2. Test OAuth flow security")
print("3. Test JWT token validation")
print("4. Check for rate limiting")
print("5. Test input validation on all endpoints")
