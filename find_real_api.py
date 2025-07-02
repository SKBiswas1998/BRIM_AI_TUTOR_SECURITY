import requests
import warnings
warnings.filterwarnings("ignore")

print("="*60)
print("Finding BrimAI Backend API Endpoints")
print("="*60)

# Your project ID from the URL
project_id = "brimai-test-v1"

# Common Firebase Functions URL patterns
possible_api_urls = [
    f"https://us-central1-{project_id}.cloudfunctions.net",
    f"https://europe-west1-{project_id}.cloudfunctions.net",
    f"https://asia-northeast1-{project_id}.cloudfunctions.net",
    f"https://{project_id}.cloudfunctions.net",
    f"https://{project_id}-default-rtdb.firebaseio.com",
    f"https://firestore.googleapis.com/v1/projects/{project_id}"
]

# Common function names
common_endpoints = [
    "/api",
    "/app",
    "/v1",
    "/auth",
    "/users",
    "/quiz",
    "/api/auth/login",
    "/api/quiz",
    "/helloWorld",  # Default Firebase function
    "/.json"  # Realtime Database REST API
]

print("\n[1] Checking Firebase Functions URLs...")
print("-"*60)

found_apis = []

for base_url in possible_api_urls:
    for endpoint in common_endpoints:
        try:
            url = base_url + endpoint
            response = requests.get(url, timeout=3, verify=False)
            
            if response.status_code != 404:
                print(f"✓ Found: {url} - Status: {response.status_code}")
                found_apis.append(url)
                
                # Check if it's an actual API
                try:
                    data = response.json()
                    print(f"  Response type: JSON")
                except:
                    if "html" not in response.headers.get('Content-Type', '').lower():
                        print(f"  Response type: {response.headers.get('Content-Type', 'Unknown')}")
                        
        except requests.exceptions.ConnectionError:
            pass  # Expected for non-existent URLs
        except Exception as e:
            if "timeout" not in str(e).lower():
                print(f"Error checking {url}: {type(e).__name__}")

# Check for public Firebase config in the app
print("\n[2] Checking for Firebase Config in App...")
print("-"*60)

try:
    # Get the main app page
    response = requests.get("https://brimai-test-v1.web.app/")
    
    # Look for Firebase config in the HTML/JS
    config_patterns = [
        "apiKey",
        "authDomain", 
        "databaseURL",
        "projectId",
        "storageBucket",
        "messagingSenderId",
        "appId",
        "cloudfunctions.net"
    ]
    
    for pattern in config_patterns:
        if pattern in response.text:
            print(f"✓ Found Firebase config pattern: {pattern}")
            
            # Try to extract the actual values
            import re
            # Look for patterns like: databaseURL: "https://..."
            matches = re.findall(rf'{pattern}["\s:]+["\'](.*?)["\']', response.text)
            if matches:
                for match in matches:
                    print(f"  Value: {match}")
                    if "firebaseio.com" in match or "cloudfunctions.net" in match:
                        found_apis.append(match)
                        
except Exception as e:
    print(f"Error checking app config: {e}")

# Check common static files
print("\n[3] Checking for API Documentation...")
print("-"*60)

doc_files = [
    "/api-docs",
    "/swagger.json",
    "/openapi.json",
    "/.well-known/openapi.json",
    "/docs",
    "/api/docs"
]

for doc in doc_files:
    try:
        url = f"https://brimai-test-v1.web.app{doc}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200 and "html" not in response.headers.get('Content-Type', ''):
            print(f"✓ Found documentation: {url}")
    except:
        pass

# Summary
print("\n" + "="*60)
print("SUMMARY")
print("="*60)

if found_apis:
    print(f"\n✓ Found {len(found_apis)} potential API endpoints:")
    for api in set(found_apis):  # Remove duplicates
        print(f"  - {api}")
    print("\nNext Steps:")
    print("1. Test these endpoints with proper authentication")
    print("2. Check your Firebase Console for deployed functions")
    print("3. Look at your source code for the actual API URLs")
else:
    print("\n❌ No public API endpoints found")
    print("\nThis could mean:")
    print("1. Your backend is not deployed yet")
    print("2. The API requires authentication even for discovery")
    print("3. The API is on a custom domain")
    print("4. You're using Firebase SDK directly (no REST API)")
    
print("\nTo find your actual API:")
print("1. Check Firebase Console > Functions")
print("2. Look in your app's source code for API_URL or baseURL")
print("3. Check your .env or config files")
print("4. Run: firebase functions:list (if you have access)")
