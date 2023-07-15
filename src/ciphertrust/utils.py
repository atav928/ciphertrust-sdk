# pylint: disable=line-too-long
"""Utilities"""

import datetime
import statistics
from typing import Dict, Any
from pathlib import Path
import time
import urllib.parse
import re
import json

import validators
from requests.models import Response
import orjson

from ciphertrust.exceptions import CipherValueError
from ciphertrust.static import ENCODE


def concat_resources(dict1, dict2) -> list[dict[str, Any]]:  # type: ignore
    """Use reduce to generate a list of resources

    :param dict1: _description_
    :type dict1: _type_
    :param dict2: _description_
    :type dict2: _type_
    :return: Concatenated Resources Results
    :rtype: list[dict[str,Any]]
    """
    for key in dict2:  # type: ignore
        if key in dict1 and key == "resources":
            dict1[key] += dict2[key]
    return dict1  # type: ignore


def reformat_exception(error: Exception) -> str:
    """Reformates Exception to print out as a string pass for logging

    Args:
        error (Exception): _description_

    Returns:
        str: _description_
    """
    return f"{type(error).__name__}: {str(error)}" if error else ""


def validate_domain(domain: str) -> bool:
    """Uses validators to determine if domain is a proper domainname

    :param domain: domain to check
    :type domain: str
    :return: True|False
    :rtype: bool
    """
    return isinstance(validators.domain(domain), bool)  # type: ignore


# payload creation
def set_refresh_lifetime(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Sets Refresh Lifetime if exists

    :return: _description_
    :rtype: Dict[str,Any]
    """
    response: Dict[str, Any] = {}
    if kwargs.get("refresh_token_lifetime"):
        response["refresh_token_lifetime"] = kwargs.get("refresh_token_lifetime")
    return response


def set_refresh_token_revoke_unused_in(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Sets refresh_token_revoke_unused_in if exists.

    :return: returns refresh token revoke
    :rtype: Dict[str,Any]
    """
    response: Dict[str, Any] = {}
    if kwargs.get("refresh_token_revoke_unused_in"):
        response["refresh_token_revoke_unused_in"] = kwargs.get("refresh_token_revoke_unused_in")
    return response


def set_renew_refresh_token(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Sets renew_refresh_token default is False used to create new refresh token

    :return: _description_
    :rtype: Dict[str,Any]
    """
    response: Dict[str, Any] = {}
    response["renew_refresh_token"] = kwargs.get("renew_refresh_token", False)
    return response


def set_user_cert(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Sets User Certificate when specified in grant type

    :raises CipherValueError: _description_
    :return: _description_
    :rtype: Dict[str,Any]
    """
    response: Dict[str, Any] = {}
    try:
        # TODO: Confirm tuple value for (cert,key)
        response["cert"] = kwargs["cert"]
    except KeyError:
        raise CipherValueError("Required missing Cert for User Cert Auth")
    return response


def grant_password(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Used to create payload with password

    :raises CipherValueError: _description_
    :return: _description_
    :rtype: Dict[str,Any]
    """
    response: Dict[str, Any] = {}
    try:
        response = {
            "password": kwargs["password"],
            "username": kwargs["username"],
            "connection": kwargs.get("connection", "local_account"),
        }
        response = {**response, **set_refresh_lifetime(**kwargs)}
        # only sets if password set
        response = {**response, **set_refresh_token_revoke_unused_in(**kwargs)}
        return response
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherValueError(f"Invalid value: {error}")  # pylint: disable=raise-missing-from


def grant_refresh(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """used to refresh grant token

    :raises CipherValueError: _description_
    :return: _description_
    :rtype: Dict[str,Any]
    """
    try:
        response: Dict[str, Any] = {
            "grant_type": kwargs["grant_type"],
            "cookies": kwargs.get("cookies", False),
            "labels": kwargs.get("labels", []),
            "refresh_token": kwargs.get("refresh_token")
        }
        response = {**response, **set_refresh_lifetime(**kwargs)}
        # specific to grant refresh to generate new refresh token
        response = {**response, **set_renew_refresh_token(**kwargs)}
        return response
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherValueError(f"Invalid value: {error}")


def grant_user_cert(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Grant Toke using User Certificate

    :raises CipherValueError: _description_
    :return: _description_
    :rtype: Dict[str, Any]
    """
    try:
        response: Dict[str, Any] = {
            "grant_type": kwargs["grant_type"],
            "cookies": kwargs.get("cookies", False),
            "labels": kwargs.get("labels", []),
        }
        response = {**response, **set_refresh_lifetime(**kwargs)}
        response = {**response, **set_user_cert(**kwargs)}
        return response
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherValueError(f"Invalid value: {error}")


def grant_client_creds(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Grant Token using client credential certificate

    :raises CipherValueError: _description_
    :return: _description_
    :rtype: Dict[str, Any]
    """
    try:
        response: Dict[str, Any] = {
            "grant_type": kwargs["grant_type"],
            "cookies": kwargs.get("cookies", False),
            "labels": kwargs.get("labels", []),
        }
        response = {**response, **set_refresh_lifetime(**kwargs)}
        return response
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherValueError(f"Invalid value: {error}")


# Grant options
grant_options: Dict[str, Any] = {
    "password": grant_password,
    "refresh_token": grant_refresh,
    "user_certificate": grant_user_cert,
    "client_credential": grant_client_creds
}


def default_payload(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Set Default Payload

    :raises CipherValueError: _description_
    :return: _description_
    :rtype: Dict[str, Any]
    """
    try:
        response: Dict[str, Any] = {
            "grant_type": kwargs["grant_type"],
            "cookies": kwargs.get("cookies", False),
            "labels": kwargs.get("labels", []),
        }
        # returns the payload used to set up the AUTH Payload Body
        return {**response, **grant_options[response["grant_type"]](**kwargs)}
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherValueError(f"Invalid value: {error}")


def verify_path_exists(path_dir: str) -> bool:
    """Checks if Path exists

    :param path_dir: _description_
    :type path_dir: str
    :return: _description_
    :rtype: bool
    """
    return Path(path_dir).exists()


def verify_file_exists(filename: str) -> None:
    """Verifies that a file being passed actually exists.

    :param filename: Full Path Filename
    :type path_dir: str
    :raise: CipherValueError
    """
    if not Path(filename).is_file():
        raise CipherValueError(f"Filen does not exist: {filename}")


def return_time() -> str:
    """Gets the current time and returns it in isoformt UTC.

    :return: _description_
    :rtype: str
    """
    return f"{datetime.datetime.utcnow().isoformat()}Z"

def return_time_utc() -> str:
    """Gets the current time and returns it in isoformt UTC.

    :return: _description_
    :rtype: str
    """
    return f"{datetime.datetime.utcnow().isoformat()}Z"

def return_epoch(utc: bool=False) -> float:
    """Return current system time in epoch without any timezone info.

    :return: current system epoch time
    :rtype: float
    """
    if utc:
        return datetime.datetime.utcnow().timestamp()
    return datetime.datetime.now().timestamp()

def convert_to_epoch(date: str) -> float:
    """Convert the returned time in ISO format to epoch.

    :param date: _description_
    :type date: str
    :return: _description_
    :rtype: float
    """
    date = re.sub(r"Z", "", date, re.IGNORECASE)
    return datetime.datetime.fromisoformat(date).timestamp()


def create_error_response(error: str,
                          status_code: int,
                          start_time: float,
                          end_time: float,
                          **kwargs: Any) -> Response:
    """Creates an error response when no response comes back from request instead of raising an error.

    :param error: _description_
    :type error: str
    :param status_code: _description_
    :type status_code: int
    :param start_time: _description_
    :type start_time: float
    :param end_time: _description_
    :type end_time: float
    :return: _description_
    :rtype: Response
    """
    response = Response()
    response.encoding = ENCODE
    utc_time_diff: float = datetime.datetime.utcnow().timestamp() - datetime.datetime.now().timestamp()
    content: dict[str, Any] = {
        "error": error,
        "total": 0,
        "request_parameters": {
            "hostname": urllib.parse.urlparse(kwargs["url"]).hostname, # type: ignore
            "method": kwargs.get("method"),
            "timeout": kwargs.get("timeout"),
            "json": orjson.dumps(kwargs.get("json", {})).decode(ENCODE),  # pylint: disable=no-member
            "data": orjson.dumps(kwargs.get("data", {})).decode(ENCODE),  # pylint: disable=no-member
            "verify": bool(kwargs.get("verify")),
            "params": orjson.dumps(kwargs.get("params", {})).decode(ENCODE)  # pylint: disable=no-member
        }
    }
    response.status_code = status_code
    response.url = f"https://{urllib.parse.urlparse(kwargs['url']).hostname}/" # type: ignore
    response.elapsed = (datetime.datetime.fromtimestamp(
        end_time) - datetime.datetime.fromtimestamp(start_time))
    response.headers.update({
        "Date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(start_time + utc_time_diff)),
        "Content-Type": "application/json; charset=UTF-8",
        "Access-Control-Allow-Headers": "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range",
        "X-Processing-Time": f"{str(abs(response.elapsed.total_seconds()))}",
        "Transfer-Encoding": "chunked",
        "Connection": "keep-alive",
        "Expires": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime((start_time+utc_time_diff)+kwargs["timeout"])),
        "Access-Control-Expose-Headers": "Content-Length,Content-Range",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Cache-Control": "no-cache",
        "X-Krakend": "Version undefined",
        "X-Krakend-Completed": "false",
        "Link": kwargs["url"]})
    response._content = orjson.dumps(content)  # pylint: disable=no-member,protected-access
    return response

def format_request(request: Response, **kwargs: Any) -> dict[Any, Any]:
    """Reformat request.

    :param response: _description_
    :type response: Response
    :return: _description_
    :rtype: dict[str,Any]
    """
    start_time: float = kwargs['start_time']  # convert_to_epoch(kwargs['start_time'])
    headers: Any = json.loads(orjson.dumps(request.headers.__dict__[ # pylint: disable=no-member
                              "_store"]).decode(ENCODE)),
    json_response: dict[str, Any] = {
        "headers": headers,
        "response_statistics": {
            "iterations": kwargs.get("iterations", 1),
            "status_code": request.status_code,
            "exec_time_total": request.elapsed.total_seconds(),
            "exec_time_elapsed": request.elapsed.total_seconds(),
            "exec_time_end": return_epoch(), # datetime.datetime.utcnow().timestamp(),
            "exec_time_start": start_time,
            "x_processing_time": float(request.headers.get("X-Processing-Time")) if request.headers.get("X-Processing-Time") else None,
        },
        "request_parameters": {
            "hostname": urllib.parse.urlparse(request.url).hostname,
            "url": request.url,
            "method": kwargs.get("method"),
            "timeout": kwargs.get("timeout"),
            "json": orjson.dumps(kwargs.get("json", {})).decode(ENCODE),  # pylint: disable=no-member
            "verify": bool(kwargs.get("verify")),
            "params": orjson.dumps(kwargs.get("params", {})).decode(ENCODE)  # pylint: disable=no-member
        }
    }
    if len(kwargs.get("exec_time_elapsed_list", [])) > 1:
        json_response["response_statistics"]["exec_time_stdev"] = statistics.stdev(
            kwargs.get("exec_time_elapsed_list"))  # type: ignore
    return json_response

if __name__ == "__main__":
    valididate_list: list[str] = ["invalid", "valid-domain.example.com", "invalid_domain*.com"]
    for _ in valididate_list:
        is_valid = validate_domain(_)
