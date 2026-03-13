# src/client/app/client.py
import httpx
import json
import logging

logger = logging.getLogger(__name__)

class MessageBoardClient:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url.rstrip('/')
        self.token = None
        # Use an AsyncClient for non-blocking network I/O
        self.http_client = httpx.AsyncClient(timeout=10.0)

    async def aclose(self):
        """Close the underlying HTTP client session."""
        await self.http_client.aclose()

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
        except httpx.HTTPStatusError as e:
            error_details = {"error": str(e)}
            try:
                error_details["details"] = response.json()
            except json.JSONDecodeError:
                error_details["details"] = response.text
            return error_details
        except json.JSONDecodeError:
            return {"error": "Failed to decode JSON response", "content": response.text}

    async def login(self, username, password):
        url = f"{self.base_url}/auth/login"
        payload = {"username": username, "password": password}
        try:
            response = await self.http_client.post(url, json=payload, headers=self._make_headers(include_auth=False))
            data = self._handle_response(response)
            if data and data.get('access_token'):
                self.token = data['access_token']
                logger.info("Login successful.")
                return True, data
            else:
                logger.warning(f"Login failed: {data.get('msg') or data.get('details', 'Unknown error')}")
                return False, data
        except httpx.RequestError as e:
            logger.error(f"Login request failed: {e}")
            return False, {"error": str(e)}

    async def logout(self):
        if not self.token:
            return False, {"msg": "Not logged in."}
        url = f"{self.base_url}/auth/logout"
        try:
            response = await self.http_client.post(url, headers=self._make_headers())
            data = self._handle_response(response)
            self.token = None
            return True, data
        except httpx.RequestError as e:
            self.token = None
            return False, {"error": str(e)}

    async def get_private_messages(self):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/private"
        response = await self.http_client.get(url, headers=self._make_headers())
        return self._handle_response(response)

    def get_group_messages(self):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/group"
        response = await self.http_client.get(url, headers=self._make_headers())
        return self._handle_response(response)

    def get_public_messages(self, filter_tags=None):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/public"
        params = {}
        if filter_tags and isinstance(filter_tags, list):
            params['tags'] = ','.join(filter_tags)
        response = await self.http_client.get(url, headers=self._make_headers(), params=params)
        return self._handle_response(response)

    def subscribe_to_tags(self, tags):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/tags/subscribe"
        payload = {"tags": tags}
        response = await self.http_client.post(url, json=payload, headers=self._make_headers())
        return self._handle_response(response)

    def unsubscribe_from_tags(self, tags):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/tags/unsubscribe"
        payload = {"tags": tags}
        response = await self.http_client.post(url, json=payload, headers=self._make_headers())
        return self._handle_response(response)

    def delete_message(self, message_id):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/{message_id}"
        response = await self.http_client.delete(url, headers=self._make_headers())
        return self._handle_response(response)

    def delete_all_messages(self, confirmation_phrase):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/messages/delete_all"
        payload = {"confirmation": confirmation_phrase}
        response = await self.http_client.post(url, json=payload, headers=self._make_headers())
        return self._handle_response(response)

    def get_server_status(self):
        if not self.token: return {"error": "Not logged in"}
        url = f"{self.base_url}/api/admin/status"
        response = await self.http_client.get(url, headers=self._make_headers())
        return self._handle_response(response)
