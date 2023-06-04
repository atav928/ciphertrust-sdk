"""Models"""

from typing import Dict, List, Any, Optional, cast

from dataclasses import dataclass

from ciphertrust_sdk.static import DEFAULT_HEADERS, VALUES
from ciphertrust_sdk.exceptions import CipherValueError
from ciphertrust_sdk.utils import validate_domain

NONETYPE: None = cast(None, object())


@dataclass
class AuthParams:  # pylint: disable=missing-class-docstring
    hostname: str
    connnection: Optional[str] = NONETYPE
    cookies: Optional[bool] = NONETYPE
    domain: Optional[str] = NONETYPE
    grant_type: str = "password"
    labels: List[str] = []
    password: Optional[str] = NONETYPE
    refresh_token: Optional[str] = NONETYPE
    refresh_token_lifetime: Optional[int] = NONETYPE
    refresh_token_revoke_unused_in: Optional[int] = NONETYPE
    renew_refresh_token: bool = False
    username: Optional[str] = ""
    cert: Optional[Any] = NONETYPE
    verify: Any = True
    timeout: int = 60
    headers: Optional[Dict[str,Any]] = DEFAULT_HEADERS

    def __post_init__(self):
        """Verify correct values for: 'grant_type', 'hostname', 'verify'"""
        if self.grant_type not in VALUES:
            raise CipherValueError(f"Invalid grant type: {self.grant_type=}")
        if not any([isinstance(self.verify, bool), isinstance(self.verify, str)]):
            raise CipherValueError(f"Invalid value: {self.verify=}")
        # TODO: Verify hostname is a valid domainname
        if not validate_domain(self.hostname):
            raise CipherValueError(f"Invlalid hostname: {self.hostname}")

    def asdict(self) -> dict[str, Any]:
        """Returns dataclass as dictionary.

        :return: dataclass dictionary
        :rtype: dict[str, Any]
        """
        return {key: value for key, value in self.__dict__.items() if value is not NONETYPE}
