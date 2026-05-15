
import json
import sys
import os

# Add backend to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))

from backend.services.postman_parser import PostmanParser

def test_parser():
    postman_collection = {
        "info": {
            "name": "Test Collection",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": [
            {
                "name": "Get Users",
                "request": {
                    "method": "GET",
                    "header": [
                        {
                            "key": "Authorization",
                            "value": "Bearer token123"
                        }
                    ],
                    "url": {
                        "raw": "https://api.example.com/users",
                        "host": ["api", "example", "com"],
                        "path": ["users"]
                    }
                }
            },
            {
                "name": "Create User",
                "request": {
                    "method": "POST",
                    "header": [
                        {
                            "key": "Content-Type",
                            "value": "application/json"
                        }
                    ],
                    "body": {
                        "mode": "raw",
                        "raw": "{\"name\": \"John Doe\"}"
                    },
                    "url": {
                        "raw": "https://api.example.com/users",
                        "host": ["api", "example", "com"],
                        "path": ["users"]
                    }
                }
            }
        ]
    }

    parser = PostmanParser()
    endpoints = parser.parse_collection(json.dumps(postman_collection))
    
    print(f"Parsed {len(endpoints)} endpoints.")
    for ep in endpoints:
        print(f" - {ep['method']} {ep['url']}")

    assert len(endpoints) == 2
    assert endpoints[0]['method'] == 'GET'
    assert endpoints[0]['url'] == 'https://api.example.com/users'
    assert endpoints[1]['method'] == 'POST'
    assert endpoints[1]['url'] == 'https://api.example.com/users'
    print("Test passed!")

if __name__ == "__main__":
    test_parser()
