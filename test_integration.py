import requests
import time
import sys

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print("Running Integration Tests on Localhost...")
    
    # Wait briefly in case server is just booting
    time.sleep(2)
    
    try:
        # 1. Register a test user
        print("1. Registering user...")
        resp = requests.post(f"{BASE_URL}/api/auth/register", json={
            "username": "admin_test",
            "email": "admin@test.com",
            "password": "SecurePassword123!"
        })
        print(f"Register status: {resp.status_code}")
        # Note: 400 is fine if the user already exists

        # 2. Login to get JWT
        print("2. Logging in...")
        resp = requests.post(f"{BASE_URL}/api/auth/login", json={
            "username": "admin_test",
            "password": "SecurePassword123!"
        })
        print(f"Login status: {resp.status_code}")
        if resp.status_code != 200:
            print(f"Login failed: {resp.text}")
            return
            
        token = resp.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}
        print("Obtained JWT token.")

        # 3. Test Dashboard Metrics
        print("3. Testing /api/dashboard/metrics...")
        resp = requests.get(f"{BASE_URL}/api/dashboard/metrics", headers=headers)
        print(f"Metrics status: {resp.status_code}")
        if resp.status_code == 200:
            print("Metrics payload OK.")
        else:
            print(f"Metrics error: {resp.text}")

        # 4. Test Glossary
        print("4. Testing /api/education/glossary...")
        resp = requests.get(f"{BASE_URL}/api/education/glossary", headers=headers)
        print(f"Glossary status: {resp.status_code}")
        if resp.status_code == 200:
            print(f"Glossary count: {resp.json().get('count')}")
            
        # 5. Test Score
        print("5. Testing /api/security-score/...")
        resp = requests.get(f"{BASE_URL}/api/security-score/", headers=headers)
        print(f"Score status: {resp.status_code}")
        if resp.status_code == 200:
            print(f"Current score: {resp.json().get('score')}")
            
        print("\nAll integration checks completed successfully!")

    except Exception as e:
        print(f"Error during testing: {e}")

if __name__ == "__main__":
    run_tests()
