"""Static Variables"""

from typing import Any, Dict


ENCODE: str = "utf-8"
VALUES: list[str] = ["password", "refresh_token", "user_certificate", "client_credential"]
DEFAULT_HEADERS: Dict[str,Any] = {
    "Content-Type": "application/json"
}
