import requests
import json

print("=" * 60)
print("TESTING API EXPOSURE - DATA EXTRACTION")
print("=" * 60)

backend_url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app"

# Test 1: Extract user data without any authentication
print("\n1. Attempting to access /api/user WITHOUT authentication...")
try:
    response = requests.get(f"{backend_url}/api/user")
    print(f"   Status Code: {response.status_code}")
    
    if response.status_code == 200:
        print("   ⚠️  DATA EXPOSED! User data accessible without auth!")
        print("   📊 Data Retrieved:")
        data = response.json()
        print(json.dumps(data, indent=2)[:500] + "..." if len(str(data)) > 500 else json.dumps(data, indent=2))
except Exception as e:
    print(f"   Error: {e}")

# Test 2: Extract subjects data
print("\n2. Attempting to access /subjects/ WITHOUT authentication...")
try:
    response = requests.get(f"{backend_url}/subjects/")
    print(f"   Status Code: {response.status_code}")
    
    if response.status_code == 200:
        print("   ⚠️  DATA EXPOSED! Subjects accessible without auth!")
        data = response.json()
        print(f"   📚 Found {len(data) if isinstance(data, list) else 'some'} subjects")
        print(json.dumps(data, indent=2)[:300] + "..." if len(str(data)) > 300 else json.dumps(data, indent=2))
except Exception as e:
    print(f"   Error: {e}")

# Test 3: Try with fake authentication
print("\n3. Testing with FAKE authentication token...")
fake_headers = {"Authorization": "Bearer totally-fake-token-12345"}
try:
    response = requests.get(f"{backend_url}/api/user", headers=fake_headers)
    print(f"   Status Code: {response.status_code}")
    
    if response.status_code == 200:
        print("   🚨 CRITICAL! API accepts ANY token!")
        print("   Anyone can pretend to be authenticated!")
except Exception as e:
    print(f"   Error: {e}")

# Test 4: Extract API schema
print("\n4. Attempting to download API schema...")
try:
    response = requests.get(f"{backend_url}/openapi.json")
    if response.status_code == 200:
        schema = response.json()
        print("   ⚠️  FULL API SCHEMA EXPOSED!")
        print(f"   📋 API Title: {schema.get('info', {}).get('title')}")
        print(f"   📋 Version: {schema.get('info', {}).get('version')}")
        
        # List all endpoints
        paths = schema.get('paths', {})
        print(f"\n   🔍 Found {len(paths)} endpoints:")
        for path, methods in list(paths.items())[:10]:  # First 10
            print(f"      - {path}: {list(methods.keys())}")
        if len(paths) > 10:
            print(f"      ... and {len(paths) - 10} more endpoints")
            
        # Check for sensitive endpoints
        sensitive_keywords = ['admin', 'user', 'password', 'token', 'secret', 'private']
        print("\n   🎯 Potentially sensitive endpoints:")
        for path in paths:
            if any(keyword in path.lower() for keyword in sensitive_keywords):
                print(f"      - {path}")
except Exception as e:
    print(f"   Error: {e}")

# Test 5: Try to enumerate users (if possible)
print("\n5. Attempting user enumeration...")
test_ids = [1, 2, 3, "admin", "test"]
for user_id in test_ids:
    try:
        response = requests.get(f"{backend_url}/api/user/{user_id}")
        if response.status_code == 200:
            print(f"   ✓ User ID '{user_id}' exists!")
        elif response.status_code == 404:
            print(f"   ✗ User ID '{user_id}' not found")
    except:
        pass

print("\n" + "=" * 60)
print("SUMMARY: Your API is completely exposed if any data was retrieved above!")
print("=" * 60)