"""Request API"""

from typing import Any, Dict
import orjson

import requests
from requests import HTTPError, Response

from ciphertrust.auth import Auth, refresh_token
from ciphertrust.exceptions import (CipherAPIError, CipherMissingParam)
from ciphertrust.static import DEFAULT_HEADERS, ENCODE
from ciphertrust.utils import reformat_exception


@refresh_token
def ctm_request(auth: Auth, **kwargs: Dict[str, Any]) -> Dict[str, Any]:  # pylint: disable=too-many-locals
    """_summary_

    Args:
        token (Auth): Auth class that is used to refresh bearer token upon expiration.
        url_type (str): specify the api call
        method (str): specifies the type of HTTPS method used
        params (dict, optional): specifies parameters passed to request
        data (str, optional): specifies the data being sent
        verify (str|bool, optional): sets request to verify with a custom
         cert bypass verification or verify with standard library. Defaults to True
        timeout (int, optional): sets API call timeout. Defaults to 60
        delete_object (str, required|optional): Required if method is DELETE
        put_object (str, required|optional): Required if method is PUT
        limit (int, Optional): The maximum number of results
        offset (int, Optional): The offset of the result entry
        get_object (str, Optional): Used if method is "GET", but additional path parameters required
    Returns:
        _type_: _description_
    """
    try:
        method: str = kwargs.pop('method')  # type: ignore
        url: str = kwargs.pop('url')  # type: ignore
        timeout: int = kwargs.pop('timeout', 60)  # type: ignore
        verify: Any = kwargs.pop('verify', True)
        params: Dict[str, Any] = kwargs.pop('params', {})
        data: Any = kwargs.pop('data', None)  # type: ignore
        headers: Dict[str, Any] = kwargs.pop("headers", DEFAULT_HEADERS)
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherMissingParam(error)  # pylint: disable=raise-missing-from
    if data:
        data: str = orjson.dumps(data).decode(ENCODE)  # pylint: disable=no-member
    # Add auth to header
    headers["Authorization"] = f"Bearer {auth.token}"
    response = requests.request(method=method,
                                url=url,
                                headers=headers,
                                data=data,
                                params=params,
                                verify=verify,
                                timeout=timeout)
    # cipher_logger.debug("Response Code=%s|Full Response=%s",
    #                     str(response.status_code), response.text.rstrip())
    api_raise_error(response=response)
    #if response.status_code == 204:
    #    json_response = {"message": "Data Created",
    #                     "code": response.status_code}
    #else:
    # Sample test
    # TODO: Replace with logger
    print(f"status={response.status_code}|response={response.json()}")
    json_response = response.json()
    return json_response


def api_raise_error(response: Response) -> None:
    """Raises error if response not what was expected

    Args:
        response (Response): _description_

    Raises:
        CipherPermission: _description_
        CipherAPIError: _description_
    """
    try:
        response.raise_for_status()
    except HTTPError as err:
        error: str = reformat_exception(err)
        raise CipherAPIError(f"{error=}|response={response.text}")
    # if response.status_code == 403:
        # message = response.json().get("message", "Permission Denied")
        # cipher_logger.error("CipherPermission: %s", message)
        # raise CipherPermission(message)
    # if not (response.status_code >= 200 and response.status_code < 299):
        # cipher_logger.error("Status Code: %s| Error: %s", str(
        #    response.status_code), response.json())
        # raise CipherAPIError(response.json())
