# app/client.py
# This file contains the Python client class for interacting with the message board server API.
import requests
import json

class MessageBoardClient:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url.rstrip('/')
        self.token = None # JWT token

    def _make_headers(self, include_auth=True):
        """Helper to create request headers."""
        headers = {"Content-Type": "application/json"}
        if include_auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _handle_response(self, response):
        """Helper to handle API responses."""
        try:
            response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
            if response.content: # Check if there is content to decode
                 # Handle cases where response might be empty but successful (e.g., 204 No Content)
                if response.status_code == 204:
                    return {"status": "success", "message": "Operation successful, no content returned."}
                return response.json()
            return {"status": "success", "message": "Operation successful, no content returned."}
        except requests.exceptions.HTTPError as e:
            error_details = {"error": str(e)}
            try: # Try to get more details from response body if available
                error_details["details"] = response.json()
            except json.JSONDecodeError: # If response body is not JSON
                error_details["details"] = response.text
            return error_details
        except json.JSONDecodeError: # If response is not JSON but status was 2xx
            return {"error": "Failed to decode JSON response", "content": response.text}


    def login(self, username, password):
        """Logs in the user and stores the JWT token."""
        url = f"{self.base_url}/auth/login"
        payload = {"username": username, "password": password}
        try:
            response = requests.post(url, json=payload, headers=self._make_headers(include_auth=False))
            data = self._handle_response(response)
            if data and data.get('access_token'):
                self.token = data['access_token']
                print("Login successful.")
                return True, data
            else:
                print(f"Login failed: {data.get('msg') or data.get('details', 'Unknown error')}")
                return False, data
        except requests.exceptions.RequestException as e:
            print(f"Login request failed: {e}")
            return False, {"error": str(e)}

    def logout(self):
        """Logs out the user (client-side token removal and server notification)."""
        if not self.token:
            print("Not logged in.")
            return False, {"msg": "Not logged in."}
        
        url = f"{self.base_url}/auth/logout"
        try:
            response = requests.post(url, headers=self._make_headers())
            data = self._handle_response(response)
            self.token = None # Clear token regardless of server response for client-side logout
            print(f"Logout attempt: {data.get('msg', data)}")
            return True, data # Server might confirm or just acknowledge
        except requests.exceptions.RequestException as e:
            print(f"Logout request failed: {e}")
            # Still clear token client-side
            self.token = None
            return False, {"error": str(e)}

    # --- Message Sending Methods ---
    def send_private_message(self, recipient_username, content):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/private"
        payload = {"recipient_username": recipient_username, "content": content}
        response = requests.post(url, json=payload, headers=self._make_headers())
        return self._handle_response(response)

    def send_group_message(self, recipient_usernames, content):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/group"
        payload = {"recipient_usernames": recipient_usernames, "content": content}
        response = requests.post(url, json=payload, headers=self._make_headers())
        return self._handle_response(response)

    def send_public_message(self, content, tags=None):
        if not self.token: return {"error": "Not logged in"}
        if tags is None: tags = []
        url = f"{self.base_url}/api/messages/public"
        payload = {"content": content, "tags": tags}
        response = requests.post(url, json=payload, headers=self._make_headers())
        return self._handle_response(response)

    # --- Message Retrieval Methods ---
    def get_private_messages(self):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/private"
        response = requests.get(url, headers=self._make_headers())
        return self._handle_response(response)

    def get_group_messages(self):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/group"
        response = requests.get(url, headers=self._make_headers())
        return self._handle_response(response)

    def get_public_messages(self, filter_tags=None): # filter_tags can be a list
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/public"
        params = {}
        if filter_tags and isinstance(filter_tags, list):
            params['tags'] = ','.join(filter_tags) # Server expects comma-separated string
        
        response = requests.get(url, headers=self._make_headers(), params=params)
        return self._handle_response(response)

    # --- Tag Subscription Methods ---
    def subscribe_to_tags(self, tags):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/tags/subscribe"
        payload = {"tags": tags}
        response = requests.post(url, json=payload, headers=self._make_headers())
        return self._handle_response(response)

    def unsubscribe_from_tags(self, tags):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/tags/unsubscribe"
        payload = {"tags": tags}
        response = requests.post(url, json=payload, headers=self._make_headers())
        return self._handle_response(response)

    # --- Message Deletion Method ---
    def delete_message(self, message_id):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/{message_id}"
        response = requests.delete(url, headers=self._make_headers())
        return self._handle_response(response)

    # --- Admin Method ---
    def get_server_status(self): # Assumes admin is logged in
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/admin/status"
        response = requests.get(url, headers=self._make_headers())
        return self._handle_response(response)


