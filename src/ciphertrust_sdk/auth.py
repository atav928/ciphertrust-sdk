# pylint: disable=missing-function-docstring
"""Authorization"""

from typing import Dict, Any, List
import time
# from urllib.parse import urlparse

import jwt
import requests
from requests import Response
import orjson

from ciphertrust_sdk import config
from ciphertrust_sdk.static import ENCODE
from ciphertrust_sdk.models import AuthParams
from ciphertrust_sdk.utils import default_payload, reformat_exception
from ciphertrust_sdk.exceptions import (CipherAPIError, CipherAuthError, CipherValueError)


class Auth:
    """Cipher Trust Auth

    :raises CipherValueError: _description_
    :raises CipherAuthError: _description_
    :raises CipherAPIError: _description_
    :return: _description_
    :rtype: _type_
    """
    method: str = "POST"
    connection: str
    expiration: int
    refreshparams: Dict[str, Any] = {}
    token: Dict[str, Any] = {}

    def __init__(self, **kwargs: Dict[str, Any]) -> None:
        self.authparams: Dict[str, Any] = AuthParams(**kwargs).asdict() # type: ignore
        try:
            self.hostname: str = self.authparams.pop("hostname")
            self.timeout: int = self.authparams.pop("timeout")
            self.verify: Any = self.authparams.pop("verify")
            self.headers: Dict[str, Any] = self.authparams.pop("headers")
        except KeyError as err:
            error: str = reformat_exception(err)
            raise CipherValueError(f"Invalid value: {error}")
        self.payload: Dict[str, Any] = self._create_payload(**self.authparams)
        self.url: str = config.AUTH.format(self.hostname)
        self.gen_token()

    def _create_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        response: Dict[str, Any] = default_payload(**payload)
        return response

    def _jwt_decode(self, jwt_token: str) -> Dict[str, Any]:
        jwt_decrypted: dict[str, Any] = jwt.decode(jwt_token,  # type: ignore
                                                   options={"verify_signature": False})
        self.expiration = jwt_decrypted["exp"]
        return jwt_decrypted

    def gen_token(self) -> None:
        """_summary_

        :return: _description_
        :rtype: Dict[str,Any]
        """
        response: Response = requests.request(method=self.method,
                                              url=self.url,
                                              data=orjson.dumps(self.payload).decode(  # pylint: disable=no-member
                                                  ENCODE),
                                              timeout=self.timeout,
                                              verify=self.verify)
        jwt_decode: Dict[str, Any] = self._jwt_decode(response.json()["jwt"])
        response_json: Dict[str, Any] = response.json()
        response_json["jwt_decode"] = jwt_decode
        self.token: Dict[str, Any] = response_json

    def refresh_token(self) -> None:
        # Update to refresh
        new_params = {
            "grant_type": "refresh_token",
            "refresh_token": self.token["refresh_token"],
        }
        self.refreshparams: dict[str, Any] = AuthParams(**new_params).asdict()
        payload: Dict[str, Any] = self._create_payload(self.refreshparams)
        response: Response = requests.request(method=self.method,
                                              url=self.url,
                                              data=orjson.dumps(payload).decode(  # pylint: disable=no-member
                                                  ENCODE),
                                              timeout=self.timeout,
                                              verify=self.verify)
        jwt_decode: Dict[str, Any] = self._jwt_decode(response.json()["jwt"])
        response_json: Dict[str,Any] = response.json()
        response_json["jwt_decode"] = jwt_decode
        self.token = response_json

    def api_raise_error(self, response: Response) -> None:
        """Raises error if response not what was expected

        :param response: Request Response
        :type response: Response
        :raises CipherAuthError: Authorization Error
        :raises CipherAPIError: Generic API Error
        """
        if response.status_code == 403:
            message = response.json().get("message", "Permission Denied")
            raise CipherAuthError(message)
        if not (response.status_code >= 200 or response.status_code < 299):
            raise CipherAPIError(response.json())


# refersh token decorator
def refresh_token(decorated):  # type: ignore
    def wrapper(*args: List[Any], **kwargs: Dict[str, Any]) -> Any:
        try:
            auth: Auth = args.pop(0) if isinstance(  # type: ignore
                args[0], Auth) else kwargs.pop("auth")  # type: ignore
            if auth.expiration <= time.time():
                auth.refresh_token()
                kwargs["auth"] = auth # type: ignore
        except KeyError:
            raise CipherAuthError(f"Invalid Authorization {auth}")
        return decorated(*args, **kwargs)
    return wrapper
