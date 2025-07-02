import requests
import warnings
warnings.filterwarnings("ignore")

print("="*50)
print("BrimAI Security Test - Starting...")
print("="*50)

base_url = "https://brimai-test-v1.web.app"

# Test 1: Check if API endpoints exist
print("\n[1] Checking API Endpoints...")
api_endpoints = [
    "/api/auth/login",
    "/api/quiz",
    "/api/dashboard",
    "/api/revision",
    "/api/explain"
]

for endpoint in api_endpoints:
    try:
        url = base_url + endpoint
        response = requests.get(url, verify=False, timeout=3)
        print(f"   {endpoint} - Status: {response.status_code}")
    except:
        print(f"   {endpoint} - Not accessible")

# Test 2: Check authentication
print("\n[2] Testing Authentication Requirements...")
protected_endpoints = ["/api/dashboard", "/api/quiz/results"]

for endpoint in protected_endpoints:
    try:
        url = base_url + endpoint
        # Test without auth header
        response = requests.get(url, verify=False, timeout=3)
        
        if response.status_code == 200:
            print(f"   [VULNERABLE] {endpoint} - No authentication required!")
        elif response.status_code in [401, 403]:
            print(f"   [SECURE] {endpoint} - Authentication required")
        else:
            print(f"   {endpoint} - Status: {response.status_code}")
    except:
        print(f"   {endpoint} - Error accessing")

print("\n" + "="*50)
print("Basic security scan complete!")
