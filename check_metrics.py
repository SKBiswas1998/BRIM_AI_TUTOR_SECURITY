import requests
import json

print("Checking /metrics endpoint...")
response = requests.get("https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app/metrics")

if response.status_code == 200:
    print("\n METRICS ENDPOINT EXPOSED!")
    print("-"*50)
    print("Content preview:")
    content = response.text[:1000]
    print(content)
    
    # Check for sensitive data
    sensitive_keywords = ["password", "token", "key", "secret", "api", "database", "memory", "cpu"]
    found_keywords = [kw for kw in sensitive_keywords if kw in response.text.lower()]
    
    if found_keywords:
        print(f"\n  Found sensitive keywords: {found_keywords}")
else:
    print(f"Metrics endpoint status: {response.status_code}")
