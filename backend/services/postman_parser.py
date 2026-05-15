import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class PostmanParser:
    """Parser for Postman Collections to extract API endpoints and details."""

    @staticmethod
    def parse_collection(collection_json: str) -> List[Dict[str, Any]]:
        """
        Parses a Postman Collection JSON string and returns a list of endpoints.
        Supports Collection v2.0 and v2.1.
        """
        try:
            data = json.loads(collection_json)
            endpoints = []
            
            # Postman collections can have nested folders
            def walk_items(items):
                for item in items:
                    if "item" in item:
                        # It's a folder, recurse
                        walk_items(item["item"])
                    elif "request" in item:
                        # It's a request
                        req = item["request"]
                        url_data = req.get("url", {})
                        
                        # Handle both string and object URLs
                        if isinstance(url_data, str):
                            url = url_data
                            method = req.get("method", "GET")
                        else:
                            # It's a URL object
                            raw_url = url_data.get("raw", "")
                            method = req.get("method", "GET")
                            url = raw_url
                        
                        endpoints.append({
                            "name": item.get("name", "Unnamed Request"),
                            "url": url,
                            "method": method,
                            "description": item.get("description", ""),
                            "headers": req.get("header", []),
                            "body": req.get("body", {}),
                        })
            
            items = data.get("item", [])
            walk_items(items)
            
            return endpoints
        except Exception as e:
            logger.error(f"Failed to parse Postman collection: {e}")
            return []
