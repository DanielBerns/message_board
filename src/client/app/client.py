# app/client.py
import requests
import json
import logging

logger = logging.getLogger(__name__)

class MessageBoardClient:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url.rstrip('/')
        self.token = None # JWT token

    def _make_headers(self, include_auth=True):
        headers = {"Content-Type": "application/json"}
        if include_auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _handle_response(self, response):
        try:
            response.raise_for_status()
            if response.content:
                if response.status_code == 204:
                    return {"status": "success", "message": "Operation successful, no content returned."}
                return response.json()
            return {"status": "success", "message": "Operation successful, no content returned."}
        except requests.exceptions.HTTPError as e:
            error_details = {"error": str(e)}
            try:
                error_details["details"] = response.json()
            except json.JSONDecodeError:
                error_details["details"] = response.text
            return error_details
        except json.JSONDecodeError:
            return {"error": "Failed to decode JSON response", "content": response.text}

    def login(self, username, password):
        url = f"{self.base_url}/auth/login"
        payload = {"username": username, "password": password}
        try:
            response = requests.post(url, json=payload, headers=self._make_headers(include_auth=False))
            data = self._handle_response(response)
            if data and data.get('access_token'):
                self.token = data['access_token']
                logger.info("Login successful.")
                return True, data
            else:
                logger.warning(f"Login failed: {data.get('msg') or data.get('details', 'Unknown error')}")
                return False, data
        except requests.exceptions.RequestException as e:
            logger.error(f"Login request failed: {e}")
            return False, {"error": str(e)}

    def logout(self):
        if not self.token:
            logger.warning("Not logged in.")
            return False, {"msg": "Not logged in."}

        url = f"{self.base_url}/auth/logout"
        try:
            response = requests.post(url, headers=self._make_headers())
            data = self._handle_response(response)
            self.token = None
            logger.info(f"Logout attempt: {data.get('msg', data)}")
            return True, data
        except requests.exceptions.RequestException as e:
            logger.error(f"Logout request failed: {e}")
            self.token = None
            return False, {"error": str(e)}

    # ... (Keep existing send/get message methods exactly as they were, they don't use print)
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

    def get_public_messages(self, filter_tags=None):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/public"
        params = {}
        if filter_tags and isinstance(filter_tags, list):
            params['tags'] = ','.join(filter_tags)
        response = requests.get(url, headers=self._make_headers(), params=params)
        return self._handle_response(response)

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

    def delete_message(self, message_id):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/{message_id}"
        response = requests.delete(url, headers=self._make_headers())
        return self._handle_response(response)

    def delete_all_messages(self, confirmation_phrase):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/delete_all"
        payload = {"confirmation": confirmation_phrase}
        response = requests.post(url, json=payload, headers=self._make_headers())
        return self._handle_response(response)

    def get_server_status(self):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/admin/status"
        response = requests.get(url, headers=self._make_headers())
        return self._handle_response(response)
