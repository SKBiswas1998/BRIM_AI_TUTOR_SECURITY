import requests
from bs4 import BeautifulSoup
import re
import json

print("="*60)
print("FRONTEND ANALYSIS - EXTRACTING SECRETS")
print("="*60)

frontend_url = "https://brimai-test-v1.web.app"

# Get the main page
response = requests.get(frontend_url)
soup = BeautifulSoup(response.text, 'html.parser')

# Find all script tags
scripts = soup.find_all('script')

print(f"\nFound {len(scripts)} script tags")

# Download and analyze main JS bundle
for script in scripts:
    if script.get('src') and 'main' in script.get('src'):
        js_url = script['src']
        if js_url.startswith('/'):
            js_url = frontend_url + js_url
            
        print(f"\nAnalyzing: {js_url}")
        
        js_response = requests.get(js_url)
        js_content = js_response.text
        
        print(f"JavaScript size: {len(js_content)} bytes")
        
        # Search for interesting patterns
        patterns = {
            "API URLs": r'https?://[a-zA-Z0-9\-\.]+\.(?:run\.app|cloudfunctions\.net|firebaseapp\.com)[/a-zA-Z0-9\-]*',
            "API Keys": r'["\']?[A-Za-z0-9_\-]{20,}["\']?',
            "Endpoints": r'["\'][/]api[/][a-zA-Z0-9\-/]+["\']',
            "Firebase Config": r'apiKey["\s:]+["\'](.*?)["\']',
            "Secrets": r'(?:secret|token|key|password)["\s:]+["\'](.*?)["\']',
            "Base URLs": r'(?:baseURL|BASE_URL|apiUrl|API_URL)["\s:]+["\'](.*?)["\']'
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                print(f"\n{pattern_name} found:")
                unique_matches = list(set(matches))[:10]  # First 10 unique
                for match in unique_matches:
                    if len(match) < 100:  # Don't print huge strings
                        print(f"  - {match}")
                        
        # Look for quiz/subject data
        quiz_patterns = [
            r'subjects["\s:]+\[(.*?)\]',
            r'questions["\s:]+\[(.*?)\]',
            r'answers["\s:]+\{(.*?)\}',
            r'topics["\s:]+\[(.*?)\]'
        ]
        
        for pattern in quiz_patterns:
            matches = re.findall(pattern, js_content, re.DOTALL)
            if matches:
                print(f"\nFound embedded data: {pattern}")
                print(f"  Preview: {matches[0][:100]}...")

print("\nChecking for exposed development files...")

# Check for common exposed files
test_files = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.json",
    "/package.json",
    "/.git/config",
    "/robots.txt",
    "/sitemap.xml"
]

for file in test_files:
    try:
        response = requests.get(frontend_url + file, timeout=3)
        if response.status_code == 200 and "<!doctype html>" not in response.text.lower():
            print(f"\n✓ FOUND: {file}")
            print(f"  Content: {response.text[:200]}...")
    except:
        pass
