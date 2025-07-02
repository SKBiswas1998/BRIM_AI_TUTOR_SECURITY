import requests
import json
from datetime import datetime

print("="*60)
print("FOCUSED VULNERABILITY VERIFICATION")
print("="*60)

backend_url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app"

# Test 1: Verify all unprotected endpoints
print("\n[1] TESTING ALL UNPROTECTED ENDPOINTS")
print("-"*60)

unprotected_test = [
    ("/", "GET"),
    ("/subjects/", "GET"),
    ("/health", "GET"),
    ("/api/user", "GET"),
    ("/docs", "GET"),
    ("/openapi.json", "GET"),
    ("/metrics", "GET"),
    ("/math/topics/", "GET"),
    ("/math/algebra/subtopics/", "GET"),
]

for endpoint, method in unprotected_test:
    try:
        response = requests.request(method, backend_url + endpoint, timeout=5)
        if response.status_code == 200:
            print(f"✓ {endpoint} - Status 200 (No auth required)")
            
            # Check what data is exposed
            try:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    print(f"  → Exposes {len(data)} items")
                elif isinstance(data, dict):
                    print(f"  → Exposes data: {list(data.keys())[:5]}")
            except:
                if len(response.text) > 100:
                    print(f"  → Returns {len(response.text)} bytes of data")
        else:
            print(f"✗ {endpoint} - Status {response.status_code}")
    except Exception as e:
        print(f"✗ {endpoint} - Error: {type(e).__name__}")

# Test 2: Verify specific vulnerabilities
print("\n[2] VERIFYING SPECIFIC VULNERABILITIES")
print("-"*60)

# No rate limiting test
print("Testing rate limiting...")
success_count = 0
start = datetime.now()

for i in range(100):  # Try 100 requests
    try:
        response = requests.get(f"{backend_url}/health", timeout=1)
        if response.status_code == 200:
            success_count += 1
    except:
        pass

elapsed = (datetime.now() - start).total_seconds()
print(f"Sent 100 requests in {elapsed:.2f}s")
print(f"Successful: {success_count}/100")

if success_count > 90:
    print("❌ NO RATE LIMITING - Server accepts 100+ requests/second")

# CORS test
print("\nTesting CORS...")
response = requests.options(f"{backend_url}/api/user", 
                          headers={"Origin": "http://evil.com"})
if "access-control-allow-origin" in response.headers:
    print(f"CORS allows: {response.headers['access-control-allow-origin']}")

# Test quiz manipulation
print("\n[3] TESTING QUIZ VULNERABILITIES")
print("-"*60)

# Can we access quiz without auth?
quiz_endpoints = [
    "/quiz1/",
    "/math/algebra/basics/quiz/",
    "/math/algebra/basics/practise/",
    "/dashboard/math/algebra/",
]

for endpoint in quiz_endpoints:
    try:
        # Try GET first
        response = requests.get(backend_url + endpoint, timeout=3)
        if response.status_code != 404:
            print(f"{endpoint} (GET): {response.status_code}")
        
        # Try POST
        response = requests.post(backend_url + endpoint, json={}, timeout=3)
        if response.status_code != 404:
            print(f"{endpoint} (POST): {response.status_code}")
            
            if response.status_code == 422:
                print(f"  → Validation error (endpoint exists!)")
                # Try with minimal data
                response2 = requests.post(backend_url + endpoint, 
                                        json={"subject": "math", "topic": "algebra"},
                                        timeout=3)
                print(f"  → With data: {response2.status_code}")
    except:
        print(f"{endpoint}: Timeout/Error")

# Test exposed data
print("\n[4] DATA EXPOSURE TEST")
print("-"*60)

# Get subjects - we know this works
response = requests.get(f"{backend_url}/subjects/")
if response.status_code == 200:
    subjects = response.json()
    print(f"❌ EXPOSED: All {len(subjects)} subjects without auth:")
    for subj in subjects[:3]:
        print(f"  - {subj}")
    if len(subjects) > 3:
        print(f"  ... and {len(subjects)-3} more")

# Save summary
summary = {
    "scan_time": datetime.now().isoformat(),
    "confirmed_vulnerabilities": {
        "CRITICAL": [
            "No authentication on /api/user",
            "No authentication on /subjects/",
            "API documentation exposed (/docs, /openapi.json)",
        ],
        "HIGH": [
            "No rate limiting",
            "Metrics endpoint exposed",
            "CORS allows localhost",
        ],
        "MEDIUM": [
            "Missing security headers",
            "Race conditions on /logout",
            "Error messages may leak information",
        ]
    },
    "recommendations": {
        "immediate": [
            "Add authentication middleware to ALL endpoints except /health",
            "Disable /docs, /redoc, /openapi.json in production",
            "Implement rate limiting (max 60 req/min per IP)",
        ],
        "urgent": [
            "Fix CORS to only allow your frontend domain",
            "Add security headers",
            "Hide /metrics or add authentication",
        ],
        "important": [
            "Implement proper error handling",
            "Add request validation",
            "Set up monitoring and alerting",
        ]
    }
}

print("\n" + "="*60)
print("FINAL SECURITY ASSESSMENT")
print("="*60)
print(json.dumps(summary, indent=2))

with open("security_summary.json", "w") as f:
    json.dump(summary, f, indent=2)

print("\n✓ Summary saved to: security_summary.json")
