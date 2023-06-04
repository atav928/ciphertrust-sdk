"""Authorization"""


from typing import Dict, Any
# from urllib.parse import urlparse

import jwt
import requests
from requests import Response
import orjson

from ciphertrust_sdk import config
from ciphertrust_sdk.static import ENCODE
from ciphertrust_sdk.models import AuthParams
from ciphertrust_sdk.utils import reformat_exception
from ciphertrust_sdk.exceptions import (CipherAPIError, CipherAuthError, CipherValueError)


class Auth:
    method: str = "POST"
    connection: str
    token: Dict[str, Any] = {}

    def __init__(self, **kwargs: Dict[str, Any]) -> None:
        self.authparams: Dict[str, Any] = AuthParams(**kwargs).asdict()
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
        return jwt.decode("token", options={"verify_signature": False})

    def gen_token(self) -> Dict[str, Any]:
        """_summary_

        :return: _description_
        :rtype: Dict[str,Any]
        """
        response: Response = requests.request(method=self.method,
                                              url=self.url,
                                              data=orjson.dumps(self.payload).decode(
                                                  ENCODE),  # pylint: disable=no-member
                                              timeout=self.timeout,
                                              verify=self.verify)
        jwt_decode: Dict[str, Any] = self._jwt_decode(response.json()["jwt"])
        response_json: Dict[str, Any] = response.json()
        response_json["jwt_decode"] = jwt_decode
        self.token: Dict[str, Any] = response_json
        return response_json

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
def refresh_token(decorated):
    def wrapper(*args: List[Any], **kwargs: Dict[str, Any]):
        try:
            token: Auth = args.pop(0) if isinstance(args[0], Auth) else kwargs.pop("auth")
            if token:
                pass
        except KeyError:
            raise CipherAuthError(f"Invalid Authorization {token=}")
        return decorated(*args, **kwargs)
    return wrapper
