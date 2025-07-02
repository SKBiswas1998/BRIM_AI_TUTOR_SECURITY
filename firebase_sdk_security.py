import requests
from bs4 import BeautifulSoup
import re
import json

print("="*60)
print("BrimAI Firebase SDK Security Analysis")
print("="*60)

# Get the main app
response = requests.get("https://brimai-test-v1.web.app/")
soup = BeautifulSoup(response.text, 'html.parser')

# Find all script tags
scripts = soup.find_all('script')

print("\n[1] Analyzing JavaScript bundles...")
print("-"*60)

firebase_config = {}
security_issues = []

for script in scripts:
    if script.get('src'):
        script_url = script['src']
        if script_url.startswith('/'):
            script_url = f"https://brimai-test-v1.web.app{script_url}"
        
        print(f"Checking: {script_url}")
        
        try:
            js_response = requests.get(script_url, timeout=10)
            js_content = js_response.text[:50000]  # First 50KB
            
            # Look for Firebase config
            firebase_patterns = {
                'apiKey': r'apiKey["\s:]+["\'](.*?)["\']',
                'authDomain': r'authDomain["\s:]+["\'](.*?)["\']',
                'projectId': r'projectId["\s:]+["\'](.*?)["\']',
                'databaseURL': r'databaseURL["\s:]+["\'](.*?)["\']',
                'storageBucket': r'storageBucket["\s:]+["\'](.*?)["\']',
                'appId': r'appId["\s:]+["\'](.*?)["\']'
            }
            
            for key, pattern in firebase_patterns.items():
                matches = re.findall(pattern, js_content)
                if matches:
                    firebase_config[key] = matches[0]
                    print(f"  ✓ Found {key}: {matches[0][:30]}...")
            
            # Security checks
            security_patterns = [
                (r'(secret|private|password|token)["\s:]+["\'](.*?)["\']', "Hardcoded secrets"),
                (r'console\.log\(.*?(password|token|secret)', "Sensitive data in console.log"),
                (r'eval\s*\(', "Use of eval()"),
                (r'innerHTML\s*=', "Potential XSS via innerHTML"),
                (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML"),
                (r'admin\s*[=:]\s*true', "Client-side admin flags"),
                (r'bypass|skip.*auth', "Authentication bypass code")
            ]
            
            for pattern, issue in security_patterns:
                if re.search(pattern, js_content, re.IGNORECASE):
                    security_issues.append(issue)
                    print(f"  ⚠️  Potential issue: {issue}")
                    
        except Exception as e:
            print(f"  Error: {str(e)[:50]}")

print("\n[2] Firebase Configuration Found:")
print("-"*60)

if firebase_config:
    print(json.dumps(firebase_config, indent=2))
    
    # Test Firestore access
    if 'projectId' in firebase_config:
        print(f"\n[3] Testing Firestore REST API...")
        print("-"*60)
        
        project_id = firebase_config['projectId']
        firestore_urls = [
            f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/users",
            f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/quiz",
            f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/questions"
        ]
        
        for url in firestore_urls:
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    print(f"  ❌ VULNERABLE: Public read access to {url}")
                    security_issues.append(f"Firestore collection publicly readable: {url}")
                elif resp.status_code == 403:
                    print(f"  ✓ Protected: {url.split('/')[-1]} collection")
                else:
                    print(f"  Status {resp.status_code}: {url.split('/')[-1]}")
            except:
                pass
else:
    print("No Firebase config found in JavaScript")

print("\n[4] Client-Side Security Analysis:")
print("-"*60)

# Check for common client-side vulnerabilities
vulnerabilities = {
    "No API Key Restrictions": firebase_config.get('apiKey') is not None,
    "Auth Domain Exposed": firebase_config.get('authDomain') is not None,
    "Database URL Exposed": firebase_config.get('databaseURL') is not None,
}

for vuln, found in vulnerabilities.items():
    if found:
        print(f"  ℹ️  {vuln} (Normal for Firebase apps)")

# Summary
print("\n" + "="*60)
print("SECURITY ASSESSMENT")
print("="*60)

if security_issues:
    print(f"\n❌ Found {len(set(security_issues))} potential security issues:")
    for issue in set(security_issues):
        print(f"  - {issue}")
else:
    print("\n✓ No obvious security issues in client-side code")

print("\n" + "="*60)
print("RECOMMENDATIONS FOR FIREBASE SDK APPS")
print("="*60)
print("""
1. FIREBASE SECURITY RULES (Most Important!):
   - Test in Firebase Console > Firestore/Realtime Database > Rules
   - Ensure rules aren't: allow read, write: if true;
   - Implement proper user authentication checks

2. CLIENT-SIDE SECURITY:
   - API keys in Firebase are meant to be public
   - Security comes from Firebase Security Rules, not hiding keys
   - Implement Firebase App Check for additional protection

3. AUTHENTICATION:
   - Test OAuth implementation
   - Check if email enumeration is possible
   - Verify token expiration

4. WHAT TO TEST NEXT:
   - Firebase Security Rules (most critical!)
   - Client-side input validation
   - Local storage for sensitive data
   - Network traffic during login/quiz
""")
