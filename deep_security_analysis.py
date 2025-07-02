import requests
import re
import json
from urllib.parse import urlparse

print("="*60)
print("BrimAI Deep Security Analysis")
print("="*60)

base_url = "https://brimai-test-v1.web.app"

# Get the main JavaScript file
js_url = "https://brimai-test-v1.web.app/static/js/main.c790bde6.js"
print(f"\n[1] Analyzing minified JavaScript...")
print("-"*60)

try:
    response = requests.get(js_url, timeout=30)
    js_content = response.text
    
    # Look for API patterns in minified code
    patterns_found = []
    
    # Common API patterns (even when minified)
    api_patterns = [
        # Backend URLs
        (r'https?://[a-zA-Z0-9\-\.]+\.cloudfunctions\.net[/a-zA-Z0-9\-]*', 'Cloud Functions URL'),
        (r'https?://[a-zA-Z0-9\-\.]+\.firebaseio\.com[/a-zA-Z0-9\-]*', 'Firebase Realtime DB'),
        (r'https?://[a-zA-Z0-9\-\.]+\.firebaseapp\.com[/a-zA-Z0-9\-]*', 'Firebase App URL'),
        (r'https?://[a-zA-Z0-9\-\.]+\.herokuapp\.com[/a-zA-Z0-9\-]*', 'Heroku Backend'),
        (r'https?://api\.[a-zA-Z0-9\-\.]+\.[a-z]+[/a-zA-Z0-9\-]*', 'Custom API Domain'),
        (r'/api/[a-zA-Z0-9\-/]+', 'Relative API Endpoints'),
        
        # Authentication patterns
        (r'["\']authorization["\']\s*:\s*["\']Bearer', 'Bearer Token Auth'),
        (r'\.getIdToken\(\)', 'Firebase Auth Token'),
        (r'googleapis\.com/identitytoolkit', 'Google Identity Toolkit'),
        (r'accounts\.google\.com', 'Google OAuth'),
        
        # Common endpoints
        (r'["\'][/]?(login|auth|signin|authenticate)["\']', 'Auth Endpoints'),
        (r'["\'][/]?(quiz|questions?|answers?)["\']', 'Quiz Endpoints'),
        (r'["\'][/]?(dashboard|profile|user)["\']', 'User Endpoints'),
        
        # Security issues
        (r'["\']password["\']\s*:\s*["\'][^"\']+["\']', 'Hardcoded Password'),
        (r'["\']apiKey["\']\s*:\s*["\'][^"\']+["\']', 'API Key'),
        (r'localStorage\.(setItem|getItem)\(["\']token', 'Token in LocalStorage'),
        (r'eval\s*\(', 'Eval Usage'),
        (r'innerHTML\s*=', 'innerHTML Usage')
    ]
    
    for pattern, description in api_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        if matches:
            patterns_found.append((description, matches[:3]))  # First 3 matches
            
    if patterns_found:
        print("Found the following patterns:")
        for desc, matches in patterns_found:
            print(f"\n✓ {desc}:")
            for match in matches:
                print(f"  - {match[:100]}")
    else:
        print("No obvious API patterns found in minified code")
        
except Exception as e:
    print(f"Error analyzing JavaScript: {e}")

# Test for common backend patterns
print(f"\n[2] Testing Common Backend Patterns...")
print("-"*60)

test_endpoints = [
    # Direct API tests
    ("POST", "/api/auth/login", {"email": "test@test.com", "password": "test"}),
    ("POST", "/auth/login", {"email": "test@test.com", "password": "test"}),
    ("POST", "/login", {"email": "test@test.com", "password": "test"}),
    ("GET", "/api/health", None),
    ("GET", "/api/status", None),
    ("GET", "/health", None),
    ("GET", "/.well-known/security.txt", None),
    
    # GraphQL
    ("POST", "/graphql", {"query": "{ __schema { types { name } } }"}),
    
    # Common misconfigurations
    ("GET", "/.env", None),
    ("GET", "/config.json", None),
    ("GET", "/api/config", None),
    ("GET", "/api/v1", None),
    ("GET", "/api", None)
]

api_found = []

for method, endpoint, data in test_endpoints:
    try:
        url = base_url + endpoint
        if method == "POST":
            response = requests.post(url, json=data, timeout=5)
        else:
            response = requests.get(url, timeout=5)
            
        # Check if it's not just the SPA
        if response.status_code != 200 or "<!doctype html>" not in response.text[:20]:
            print(f"{method} {endpoint}: Status {response.status_code}")
            
            if response.status_code in [200, 401, 403, 400]:
                api_found.append(endpoint)
                try:
                    json_response = response.json()
                    print(f"  Response: {str(json_response)[:100]}")
                except:
                    print(f"  Response: {response.text[:100]}")
                    
    except Exception as e:
        if "timeout" not in str(e).lower():
            print(f"{method} {endpoint}: {type(e).__name__}")

# Check for exposed files
print(f"\n[3] Checking for Exposed Configuration Files...")
print("-"*60)

config_files = [
    "firebase.json",
    ".firebaserc", 
    "package.json",
    "manifest.json",
    "robots.txt",
    "sitemap.xml",
    "security.txt",
    ".well-known/security.txt"
]

for file in config_files:
    try:
        response = requests.get(f"{base_url}/{file}", timeout=5)
        if response.status_code == 200 and "<!doctype html>" not in response.text[:20]:
            print(f"✓ Found: /{file}")
            if file == "manifest.json":
                try:
                    manifest = response.json()
                    print(f"  App Name: {manifest.get('name', 'Unknown')}")
                except:
                    pass
    except:
        pass

# Test authentication endpoints with different methods
print(f"\n[4] Testing Authentication Methods...")
print("-"*60)

auth_tests = [
    # Google OAuth endpoints
    ("GET", "/auth/google", None),
    ("GET", "/api/auth/google", None),
    ("GET", "/__/auth/handler", None),  # Firebase Auth
    ("GET", "/__/auth/iframe", None),   # Firebase Auth iframe
    
    # Session endpoints
    ("GET", "/api/session", None),
    ("GET", "/api/me", None),
    ("GET", "/api/user", None),
    ("GET", "/api/current-user", None)
]

for method, endpoint, data in auth_tests:
    try:
        response = requests.get(base_url + endpoint, allow_redirects=False, timeout=5)
        if response.status_code in [301, 302, 307, 308]:
            print(f"{endpoint}: Redirects to {response.headers.get('Location', 'Unknown')}")
        elif response.status_code != 200 or "<!doctype html>" not in response.text[:20]:
            print(f"{endpoint}: Status {response.status_code}")
    except:
        pass

# Summary
print(f"\n" + "="*60)
print("ANALYSIS SUMMARY")
print("="*60)

if api_found:
    print(f"\n✓ Found {len(api_found)} potential API endpoints:")
    for endpoint in api_found:
        print(f"  - {endpoint}")
else:
    print("\n❌ No traditional REST API endpoints found")
    
print(f"\nARCHITECTURE ASSESSMENT:")
print("Your app appears to be using one of these patterns:")
print("1. Firebase SDK with direct Firestore/Realtime DB access")
print("2. Server-side rendering with no exposed API")
print("3. GraphQL with a different endpoint")
print("4. WebSocket-based real-time communication")

print(f"\nNEXT STEPS:")
print("1. Use browser DevTools to monitor network traffic during:")
print("   - Login process")
print("   - Quiz taking")
print("   - Accessing protected features")
print("2. Check browser console for global variables:")
print("   - Open DevTools Console")
print("   - Type: window")
print("   - Look for: firebase, auth, api, config")
print("3. Test client-side security:")
print("   - LocalStorage manipulation")
print("   - Cookie security")
print("   - JavaScript function overriding")
