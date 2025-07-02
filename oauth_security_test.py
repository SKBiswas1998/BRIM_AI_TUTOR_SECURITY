import requests
import time
import urllib.parse

print("="*60)
print("OAuth Security Test")
print("="*60)

backend_url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app"

# Test OAuth endpoints
print("\n[1] Testing OAuth Endpoints...")

# Test open redirect
malicious_redirects = [
    "https://evil.com",
    "//evil.com",
    "https://fastapi-tutor-app-backend.evil.com"
]

for redirect in malicious_redirects:
    try:
        response = requests.get(
            f"{backend_url}/auth/google",
            params={"redirect_uri": redirect},
            allow_redirects=False,
            timeout=5
        )
        
        if response.status_code in [301, 302]:
            location = response.headers.get("Location", "")
            if "evil.com" in location:
                print(f"❌ VULNERABLE: Open redirect to {redirect}")
            else:
                print(f"✓ Protected: Redirect validated")
    except:
        pass

# Test state parameter
print("\n[2] Testing CSRF Protection...")

response = requests.get(f"{backend_url}/auth/google", allow_redirects=False)
if response.status_code in [301, 302]:
    location = response.headers.get("Location", "")
    if "state=" in location:
        print("✓ State parameter present for CSRF protection")
    else:
        print("❌ No state parameter - vulnerable to CSRF")

print("\n" + "="*60)
