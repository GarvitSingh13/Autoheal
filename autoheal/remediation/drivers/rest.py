"""REST / RESTCONF driver (RFC 8040 conventions, works for any JSON REST API)."""

from __future__ import annotations

from typing import Any

import httpx

from autoheal.config import Credentials, Endpoint

YANG_JSON = "application/yang-data+json"


class RestError(Exception):
    pass


class RestTarget:
    """A base URL plus auth: either a device's RESTCONF root or a named external system."""

    def __init__(self, base_url: str, username: str | None = None, password: str | None = None,
                 verify_tls: bool = True, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password) if username else None
        self.verify_tls = verify_tls
        self.timeout = timeout

    @classmethod
    def from_endpoint(cls, ep: Endpoint) -> "RestTarget":
        return cls(ep.base_url, ep.username, ep.password, ep.verify_tls, ep.timeout)

    @classmethod
    def for_device(cls, restconf_url: str, creds: Credentials) -> "RestTarget":
        return cls(restconf_url, creds.username, creds.password)

    async def request(self, method: str, path: str, json: Any = None) -> httpx.Response:
        url = self.base_url + (path if path.startswith("/") else "/" + path)
        headers = {"Accept": f"{YANG_JSON}, application/json"}
        if json is not None:
            headers["Content-Type"] = YANG_JSON
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=self.timeout) as client:
                return await client.request(method.upper(), url, json=json, headers=headers, auth=self.auth)
        except httpx.HTTPError as exc:
            raise RestError(f"{method.upper()} {url} failed: {exc}") from exc

    async def get_value(self, path: str, json_path: str | None) -> Any:
        resp = await self.request("GET", path)
        if resp.status_code >= 400:
            raise RestError(f"GET {path} returned HTTP {resp.status_code}")
        return extract(resp.json(), json_path)


def extract(doc: Any, json_path: str | None) -> Any:
    """Follow a dotted path (``a.b.0.c``) into a JSON document."""
    if not json_path:
        return doc
    node = doc
    for part in json_path.split("."):
        if isinstance(node, list):
            node = node[int(part)]
        elif isinstance(node, dict):
            if part not in node:
                return None
            node = node[part]
        else:
            return None
    return node
