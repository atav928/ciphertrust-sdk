# pylint: disable=missing-function-docstring,raise-missing-from
"""Authorization"""

from typing import Dict, Any
import datetime
import statistics
# from urllib.parse import urlparse

import jwt
import requests
from requests import HTTPError, Response
import orjson

from easy_logger.log_format import splunk_format

from ciphertrust import config, logger
from ciphertrust.static import ENCODE
from ciphertrust.models import AuthParams
from ciphertrust.utils import (create_error_response, default_payload,
                               reformat_exception, return_epoch)
from ciphertrust.exceptions import (CipherAPIError, CipherAuthError, CipherValueError)

cipher_log = logger.getLogger(__name__)


class Auth:
    """Cipher Trust Auth

    :raises CipherValueError: Incorrect Value provided
    :raises CipherAuthError: Authorization Error
    :raises CipherAPIError: Generic API Error
    :return: Token with authorization values
    :rtype: Auth
    """
    method: str = "POST"
    message: str
    connection: str
    issued_at: int
    expiration: float
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
    exec_time_total: float = 0.0
    exec_time_start: list[float] = []
    exec_time_end: list[float] = []
    duration: int = 240
    refresh_params: Dict[str, Any] = {}
    iterations: int = 0
    _expiration_offset: float = 15.0
    _response: Response

    def __init__(self, **kwargs: Dict[str, Any]) -> None:
        authparams: Dict[str, Any] = AuthParams(**kwargs).asdict()  # type: ignore
        try:
            self.hostname: str = authparams.pop("hostname")
            self.timeout: int = authparams.pop("timeout")
            self.verify: Any = authparams.pop("verify")
            self.headers: Dict[str, Any] = authparams.pop("headers")
            self.__renew_refresh_token: bool = authparams.pop("renew_refresh_token", False)
            self._expiration_offset: float = authparams.pop(
                "expiration_offset", self._expiration_offset)
        except KeyError as err:
            error: str = reformat_exception(err)
            raise CipherValueError(f"Invalid value: {error}")
        self.payload: Dict[str, Any] = self._create_payload(authparams)
        self.url: str = config.AUTH.format(self.hostname)
        self.gen_token()

    @property
    def renew_refresh_token(self):
        return self.__renew_refresh_token

    @renew_refresh_token.setter
    def renew_refresh_token(self, value: bool):
        if not isinstance(value, bool):  # type: ignore
            raise CipherValueError(f"Invalid value for renew_refresh_token: {value}")
        self.__renew_refresh_token = value

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
        self.message = ""
        data: str = orjson.dumps(self.payload).decode(ENCODE)  # pylint: disable=no-member
        start_time: float = return_epoch()
        self.exec_time_start.append(return_epoch())
        try:
            response: Response = self._request(data=data)
        except (Exception) as err:
            end_time = return_epoch()
            self._update_exec_time(exec_time=(end_time - start_time))
            error = reformat_exception(err)
            error_message = {
                "error": error,
                "error_type": "CipherAuthError",
                "error_response": "Bad Request"
            }
            response = self._create_error_response(error=error,
                                                   status_code=400,
                                                   start_time=start_time,
                                                   error_message=error_message)
            self._response = response
            return None
        self.exec_time_end.append(return_epoch())
        try:
            response.raise_for_status()
            self._update_exec_time(response.elapsed.total_seconds())
            end_time = return_epoch()
            cipher_log.info(
                splunk_format(
                    source="ciphertrust-sdk",
                    message="Generated Auth Token", hostname=self.hostname,
                    status_code=response.status_code,
                    exec_time_total=response.elapsed.total_seconds(),
                    exec_time_elapsed=self.exec_time_elapsed[-1],
                    exec_time_end=end_time, exec_time_start=start_time,
                    x_processing_time=response.headers.get("X-Processing-Time"),
                    url=self.url))
        except (HTTPError) as err:
            self._update_exec_time(response.elapsed.total_seconds())
            error = reformat_exception(err)
            error_message = {
                "error": error,
                "error_type": "CipherAuthError",
                "error_response": f"{response.text if response.text else response.reason}"
            }
            response = self._create_error_response(error=error,
                                                   status_code=response.status_code,
                                                   start_time=start_time,
                                                   error_message=error_message)
            self._response = response
            return None
        try:
            jwt_decode: Dict[str, Any] = self._jwt_decode(response.json()["jwt"])
        except KeyError:
            raise CipherAPIError("No token in response")
        response_json: Dict[str, Any] = response.json()
        response_json["jwt_decode"] = jwt_decode
        self._update_token_info(response_json=response_json)
        self.message = "Generated Auth Token"
        self._response = response

    def gen_refresh_token(self) -> None:
        self.message: str = ""
        self.payload: Dict[str, Any] = self._create_payload(self.refresh_authparams.asdict())
        data: str = orjson.dumps(self.payload).decode(ENCODE)  # pylint: disable=no-member
        self.exec_time_start.append(return_epoch())
        start_time = return_epoch()
        response: Response = self._request(data=data)
        self.exec_time_end.append(return_epoch())
        end_time = return_epoch()
        try:
            # self.api_raise_error(response=response)
            response.raise_for_status()
            self._update_exec_time(response.elapsed.total_seconds())
            end_time = return_epoch()
            cipher_log.info(
                splunk_format(
                    source="ciphertrust-sdk",
                    message="Generated Refresh Token", hostname=self.hostname,
                    status_code=response.status_code,
                    exec_time_total=response.elapsed.total_seconds(),
                    exec_time_elapsed=self.exec_time_elapsed[-1],
                    exec_time_end=end_time, exec_time_start=start_time,
                    x_processing_time=response.headers.get("X-Processing-Time"),
                    url=self.url))
        except (HTTPError, CipherAuthError) as err:
            self._update_exec_time(response.elapsed.total_seconds())
            error = reformat_exception(err)
            error_message = {
                "error": error,
                "error_type": "CipherAuthError",
                "error_response": f"{response.text if response.text else response.reason}"
            }
            response = self._create_error_response(error=error,
                                                   status_code=response.status_code,
                                                   start_time=start_time,
                                                   error_message=error_message)
            self._response = response
            return None
            # raise CipherAuthError(error)
        try:
            jwt_decode: Dict[str, Any] = self._jwt_decode(response.json()["jwt"])
        except KeyError:
            raise CipherAPIError("No token in response")
        response_json: Dict[str, Any] = response.json()
        response_json["jwt_decode"] = jwt_decode
        self._update_token_info(response_json=response_json)
        self.message: str = "Generated Refresh Token"
        self._response = response

    def _create_error_response(
            self, error: str, status_code: int, start_time: float, error_message: dict[str, str]):
        end_time = return_epoch()
        response: Response = create_error_response(
            error=error, status_code=status_code, start_time=start_time, end_time=end_time,
            url=self.url, timeout=self.timeout,
            params={"grant_type": self.payload.get("grant_type")})
        cipher_log.error(
            splunk_format(
                source="ciphertrust-sdk",
                hostname=self.hostname, status_code=response.status_code,
                exec_time_total=response.elapsed.total_seconds(),
                exec_time_elapsed=self.exec_time_elapsed[-1],
                exec_time_end=end_time, exec_time_start=start_time,
                x_processing_time=response.headers.get("X-Processing-Time", None),
                url=self.url,
                **error_message))
        return response

    def _update_exec_time(self, exec_time: float) -> None:
        """Updates Execution Times to track 

        :param exec_time: _description_
        :type exec_time: float
        """
        self.exec_time_total = exec_time
        self.exec_time_elapsed.append(exec_time)
        self.exec_time_min = min(self.exec_time_elapsed)
        self.exec_time_max = max(self.exec_time_elapsed)
        self.exec_time_stdev = None if len(self.exec_time_elapsed) <= 1 else statistics.stdev(self.exec_time_elapsed) # type: ignore
        self.iterations = len(self.exec_time_elapsed)

    def _update_token_info(self, response_json: Dict[str, Any]):
        # subtract 15seconds from expiraqtion to allow for room in response.
        self.expiration: float = (datetime.datetime.fromtimestamp(
            response_json["jwt_decode"]["exp"]) - datetime.timedelta(seconds=self._expiration_offset)).timestamp()
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

    @property
    def expiration_offset(self):
        return self._expiration_offset

    @expiration_offset.setter
    def expiration_offset(self, value: float):
        if value < 0:
            raise CipherValueError("Expiration Offset cannot be negative")
        self._expiration_offset = value

    @property
    def response(self):
        return self._response

    @response.setter
    def response(self, value):
        self._response = value

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
            if datetime.datetime.now().timestamp() >= auth.expiration:
                auth.gen_refresh_token()
        except KeyError:
            raise CipherAuthError(f"Invalid Authorization {auth}")
        return decorated(auth, **kwargs)  # type: ignore
    return wrapper
