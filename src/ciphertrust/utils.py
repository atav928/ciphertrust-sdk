"""Utilities"""

import time
from typing import Dict, Any

import validators

from ciphertrust.exceptions import CipherValueError

def concat_resources(dict1, dict2) -> list[dict[str,Any]]:
    """Use reduce to generate a list of resources

    :param dict1: _description_
    :type dict1: _type_
    :param dict2: _description_
    :type dict2: _type_
    :return: _description_
    :rtype: list[dict[str,Any]]
    """
    for key in dict2:
        if key in dict1 and key == "resources":
            dict1[key] += dict2[key]
    return dict1

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
    response = {}
    if kwargs.get("refresh_token_lifetime"):
        response["refresh_token_lifetime"] = kwargs.get("refresh_token_lifetime")
    return response


def set_refresh_token_revoke_unused_in(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Sets refresh_token_revoke_unused_in if exists

    :return: _description_
    :rtype: Dict[str,Any]
    """
    response = {}
    if kwargs.get("refresh_token_revoke_unused_in"):
        response["refresh_token_revoke_unused_in"] = kwargs.get("refresh_token_revoke_unused_in")
    return response


def set_renew_refresh_token(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Sets renew_refresh_token default is False used to create new refresh token

    :return: _description_
    :rtype: Dict[str,Any]
    """
    response = {}
    response["renew_refresh_token"] = kwargs.get("renew_refresh_token", False)
    return response


def set_user_cert(**kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """Sets User Certificate when specified in grant type

    :raises CipherValueError: _description_
    :return: _description_
    :rtype: Dict[str,Any]
    """
    response = {}
    try:
        # TODO: Confirm tuple value for (cert,key)
        response["cert"] = kwargs["cert"]
        return response
    except KeyError:
        raise CipherValueError("Required missing Cert for User Cert Auth")


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
        raise CipherValueError(f"Invalid value: {error}")


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
    # print(f"Checking domain validation against list: {', '.join(valididate_list)}")
    for _ in valididate_list:
        is_valid = validate_domain(_)
        # print(f"{_} is {str(is_valid)}")
