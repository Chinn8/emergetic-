#!/usr/bin/env python3
import requests
import json

def test_chat_endpoints():
    base_url = "http://127.0.0.1:8001"
    
    # First, create a user and login
    print("1. Creating user and logging in...")
    
    # Signup
    signup_data = {
        "name": "Test User",
        "email": "test@example.com", 
        "password": "testpass123"
    }
    
    try:
        signup_response = requests.post(f"{base_url}/api/auth/signup", json=signup_data)
        print(f"Signup status: {signup_response.status_code}")
        if signup_response.status_code not in [200, 201, 409]:  # 409 for user already exists
            print(f"Signup error: {signup_response.text}")
    except Exception as e:
        print(f"Signup error: {e}")
    
    # Login
    login_data = {
        "email": "test@example.com",
        "password": "testpass123"
    }
    
    try:
        login_response = requests.post(f"{base_url}/api/auth/login", json=login_data)
        print(f"Login status: {login_response.status_code}")
        
        if login_response.status_code == 200:
            token_data = login_response.json()
            token = token_data.get("token")
            print(f"Token received: {token[:20] if token else 'None'}...")
            
            # Test chat
            print("\n2. Testing chat endpoint...")
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            chat_data = {
                "message": "Hello, this is a test message!"
            }
            
            chat_response = requests.post(f"{base_url}/api/chat/send", json=chat_data, headers=headers)
            print(f"Chat status: {chat_response.status_code}")
            
            if chat_response.status_code == 200:
                chat_result = chat_response.json()
                print(f"Chat response: {json.dumps(chat_result, indent=2)}")
            else:
                print(f"Chat error: {chat_response.text}")
                
        else:
            print(f"Login failed: {login_response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_chat_endpoints()