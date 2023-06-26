# pylint: disable=missing-function-docstring,raise-missing-from
"""Authorization"""

from typing import Dict, Any
import time
import statistics
# from urllib.parse import urlparse

import jwt
import requests
from requests import HTTPError, Response
import orjson

from ciphertrust import config
from ciphertrust.static import ENCODE
from ciphertrust.models import AuthParams
from ciphertrust.utils import default_payload, reformat_exception
from ciphertrust.exceptions import (CipherAPIError, CipherAuthError, CipherValueError)

# TODO: Convert to logging module


class Auth:
    """Cipher Trust Auth

    :raises CipherValueError: Incorrect Value provided
    :raises CipherAuthError: Authorization Error
    :raises CipherAPIError: Generic API Error
    :return: Token with authorization values
    :rtype: Auth
    """
    method: str = "POST"
    connection: str
    issued_at: int
    expiration: int
    refresh_token_id: str
    refresh_token: str
    token: str
    token_type: str
    refresh_authparams: AuthParams
    auth_response: Dict[str, Any] = {}
    exec_time_elapsed: list[float] = []
    exec_time_stdev: float = 0.0
    exec_time_min: float = 0.0
    exec_time_max: float = 0.0
    exec_time: float = 0.0
    duration: int = 240
    refresh_params: Dict[str, Any] = {}

    def __init__(self, **kwargs: Dict[str, Any]) -> None:
        authparams: Dict[str, Any] = AuthParams(**kwargs).asdict()  # type: ignore
        # print(f"{authparams=}")
        try:
            self.hostname: str = authparams.pop("hostname")
            self.timeout: int = authparams.pop("timeout")
            self.verify: Any = authparams.pop("verify")
            self.headers: Dict[str, Any] = authparams.pop("headers")
            self.__renew_refresh_token: bool = authparams.pop("renew_refresh_token", False)
        except KeyError as err:
            error: str = reformat_exception(err)
            raise CipherValueError(f"Invalid value: {error}")
        self.payload: Dict[str, Any] = self._create_payload(authparams)
        self.url: str = config.AUTH.format(self.hostname)
        # print(f"{self.url}")
        self.gen_token()

    @property
    def renew_refresh_token(self):
        return self.__renew_refresh_token

    @renew_refresh_token.setter
    def renew_refresh_token(self, value: bool):
        if not isinstance(value, bool):
            raise CipherValueError(f"Invalid value for renew_refresh_token: {value}")
        self.__renew_refresh_token = value

    def _create_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # print(f"{payload=}")
        response: Dict[str, Any] = default_payload(**payload)
        # print(f"createdpayload={response}")
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
        data: str = orjson.dumps(self.payload).decode(ENCODE)  # pylint: disable=no-member
        # print(f"method={self.method}|url={self.url}|data={data}|timeout={self.timeout}|verify={self.verify}|headers={self.headers}")
        response: Response = self._request(data=data)
        # print(f"response={response.json()}|code={response.status_code}")
        self.api_raise_error(response)
        try:
            jwt_decode: Dict[str, Any] = self._jwt_decode(response.json()["jwt"])
        except KeyError:
            raise CipherAPIError("No token in response")
        self._update_exec_time(response.elapsed.total_seconds())
        response_json: Dict[str, Any] = response.json()
        response_json["jwt_decode"] = jwt_decode
        # print(f"{response_json=}")
        self._update_token_info(response_json=response_json)

    def gen_refresh_token(self) -> None:
        payload: Dict[str, Any] = self._create_payload(self.refresh_authparams.asdict())
        data: str = orjson.dumps(payload).decode(ENCODE)  # pylint: disable=no-member
        response: Response = self._request(data=data)
        # print(f"response_code{response.status_code}|response={response.json()}")
        self.api_raise_error(response=response)
        try:
            jwt_decode: Dict[str, Any] = self._jwt_decode(response.json()["jwt"])
        except KeyError:
            raise CipherAPIError("No token in response")
        self._update_exec_time(response.elapsed.total_seconds())
        response_json: Dict[str, Any] = response.json()
        response_json["jwt_decode"] = jwt_decode
        self._update_token_info(response_json=response_json)

    def _update_exec_time(self, exec_time: float) -> None:
        """Updates Execution Times to track 

        :param exec_time: _description_
        :type exec_time: float
        """
        self.exec_time = exec_time
        self.exec_time_elapsed.append(exec_time)
        self.exec_time_min = min(self.exec_time_elapsed)
        self.exec_time_max = max(self.exec_time_elapsed)
        self.exec_time_stdev = 0.0 if len(
            self.exec_time_elapsed) <= 1 else statistics.stdev(
            self.exec_time_elapsed)
    

    def _update_token_info(self, response_json: Dict[str, Any]):
        self.expiration = response_json["jwt_decode"]["exp"]
        self.issued_at = response_json["jwt_decode"]["iat"]
        self.refresh_token = response_json["refresh_token"]
        self.token = response_json["jwt"]
        self.token_type: str = response_json["token_type"]
        self.refresh_token_id = response_json["refresh_token_id"]
        # TODO: Change to dataclassifier
        self.refresh_authparams = AuthParams(grant_type="refresh_token",
                                             verify=self.verify,
                                             headers=self.headers,
                                             timeout=self.timeout,
                                             hostname=self.hostname,
                                             expiration=self.expiration,
                                             renew_refresh_token=True,
                                             **response_json)
        self.auth_response: Dict[str, Any] = response_json
        self.duration = response_json["duration"]

    def _request(self, data: str) -> Response:
        response: Response = requests.request(method=self.method,
                                              url=self.url,
                                              data=data,
                                              headers=self.headers,
                                              timeout=self.timeout,
                                              verify=self.verify)
        return response

    def api_raise_error(self, response: Response) -> None:
        """Raises error if response not what was expected

        :param response: Request Response
        :type response: Response
        :raises CipherAuthError: Authorization Error
        :raises CipherAPIError: Generic API Error
        """
        try:
            response.raise_for_status()
        except HTTPError as err:
            error: str = reformat_exception(err)
            raise CipherAPIError(f"{error=}|response={response.text}")
        if not (response.status_code >= 200 or response.status_code < 299):
            raise CipherAPIError(response.json())


# refersh token decorator
def refresh_token(decorated):  # type: ignore
    def wrapper(auth: Auth, **kwargs: Dict[str, Any]) -> Any:
        try:
            if time.time() >= auth.expiration:
                auth.gen_refresh_token()
                # print("Generatinga new token|auth.expiration=",
                #       f"{auth.expiration}|issued={auth.issued_at}")
        except KeyError:
            raise CipherAuthError(f"Invalid Authorization {auth}")
        return decorated(auth, **kwargs)
    return wrapper
