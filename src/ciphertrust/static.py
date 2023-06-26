"""Static Variables"""

from typing import Any, Dict
from httpx import Limits, Timeout


ENCODE: str = "utf-8"
VALUES: list[str] = ["password", "refresh_token", "user_certificate", "client_credential"]
DEFAULT_HEADERS: Dict[str,Any] = {
    "Content-Type": "application/json"
}
DEFAULT_LIMITS_OVERRIDE = Limits(max_connections=100, max_keepalive_connections=5)
DEFAULT_TIMEOUT_CONFIG_OVERRIDE = Timeout(timeout=None)
