"""Utilities"""

from typing import Dict, Any

import validators

from ciphertrust_sdk.exceptions import CipherValueError

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
def grant_password(**kwargs: Dict[str,Any]) -> Dict[str,Any]:
    response: Dict[str,Any] = {}
    try:
        response = {
            "password": kwargs["password"],
            "username": kwargs["username"],
            "connection": kwargs.get("connection", "local_account"),

        }
        return response
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherValueError(f"Invalid value: {error}")
    

def grant_refresh(**kwargs: Dict[str,Any]) -> Dict[str,Any]:
    try:
        response: Dict[str, Any] = {
            "grant_type": kwargs["grant_type"],
            "cookies": kwargs.get("cookies", False),
            "labels": kwargs.get("labels", []),
        }
        return response
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherValueError(f"Invalid value: {error}")   

def grant_user_cert(**kwargs: Dict[str,Any]) -> Dict[str,Any]:
    try:
        response: Dict[str, Any] = {
            "grant_type": kwargs["grant_type"],
            "cookies": kwargs.get("cookies", False),
            "labels": kwargs.get("labels", []),
        }
        return response
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherValueError(f"Invalid value: {error}")
    
def grant_client_creds(**kwargs: Dict[str,Any]) -> Dict[str,Any]:
    try:
        response: Dict[str,Any] = {
            "grant_type": kwargs["grant_type"],
            "cookies": kwargs.get("cookies", False),
            "labels": kwargs.get("labels", []),
        }
        return response
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherValueError(f"Invalid value: {error}")
    

## Grant options
grant_options: Dict[str,Any] = {
    "password": grant_password,
    "refresh_token": grant_refresh,
    "user_certificate": grant_user_cert,
    "client_credential": grant_client_creds
}

def default_payload(**kwargs: Dict[str,Any]) -> Dict[str,Any]:
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

if __name__ == "__main__":
    valididate_list: list[str] = ["invalid", "valid-domain.example.com", "invalid_domain*.com"]
    print(f"Checking domain validation against list: {', '.join(valididate_list)}")
    for _ in valididate_list:
        is_valid = validate_domain(_)
        print(f"{_} is {str(is_valid)}")
