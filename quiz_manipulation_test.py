import requests
import time

print("Quiz Logic Manipulation Tests")
print("="*40)

backend_url = "https://fastapi-tutor-app-backend-208251878692.asia-south1.run.app"

# Test 1: Submit quiz without starting
print("\n1. Submitting quiz without starting...")
response = requests.post(f"{backend_url}/quiz1/", 
                        json={"answers": {"1": "A", "2": "B", "3": "C"}},
                        timeout=5)
print(f"Response: {response.status_code}")
if response.status_code == 200:
    print("❌ VULNERABLE: Can submit quiz without starting!")

# Test 2: Submit same quiz multiple times
print("\n2. Multiple submissions test...")
for i in range(3):
    response = requests.post(f"{backend_url}/quiz1/",
                            json={"answers": {"1": "A"}, "attempt": i},
                            timeout=5)
    print(f"Attempt {i+1}: {response.status_code}")

# Test 3: Time manipulation
print("\n3. Time manipulation test...")
response = requests.post(f"{backend_url}/quiz1/",
                        json={
                            "answers": {"1": "A"},
                            "start_time": "2024-01-01T00:00:00",
                            "end_time": "2024-01-01T00:00:01",
                            "time_taken": 1
                        },
                        timeout=5)
print(f"With fake time: {response.status_code}")

# Test 4: Score injection
print("\n4. Direct score injection...")
response = requests.post(f"{backend_url}/quiz1/",
                        json={
                            "answers": {},
                            "score": 100,
                            "correct_answers": 100,
                            "percentage": 100
                        },
                        timeout=5)
print(f"Score injection: {response.status_code}")
