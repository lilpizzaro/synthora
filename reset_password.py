import requests
import json

url = 'https://synthora.onrender.com/auth/reset-password'
data = {
    'username': 'LilPizza',
    'password': 'SynthoraAI@2024'
}

headers = {
    'Content-Type': 'application/json'
}

response = requests.post(url, json=data, headers=headers)
print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}") 