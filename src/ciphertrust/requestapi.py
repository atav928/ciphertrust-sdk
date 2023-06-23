"""Request API"""

from typing import Any, Dict, List
import time
import statistics
import asyncio
import copy

import orjson
import httpx
import requests
from requests import HTTPError, Response

from ciphertrust.auth import (Auth, refresh_token)
from ciphertrust.exceptions import (CipherAPIError, CipherMissingParam)
from ciphertrust.static import DEFAULT_HEADERS, ENCODE
from ciphertrust.utils import reformat_exception


@refresh_token
def ctm_request(auth: Auth, **kwargs: Any) -> Dict[str, Any]:  # pylint: disable=too-many-locals
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
    response: Response = requests.request(method=method,
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
    # print(f"status={response.status_code}|response={response.json()}")
    json_response = {
        "exec_time": response.elapsed.total_seconds(),
        "headers": response.headers
    }
    return {**json_response, **response.json()}

@refresh_token
async def ctm_request_async(auth: Auth, **kwargs: Any) -> Dict[str, Any]:  # pylint: disable=too-many-locals
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
        client: httpx.AsyncClient = kwargs["client"]
        url: str = kwargs.pop('url')  # type: ignore
        params: Dict[str, Any] = kwargs['params']
        headers: Dict[str, Any] = kwargs.pop("headers", DEFAULT_HEADERS)
    except KeyError as err:
        error: str = reformat_exception(err)
        raise CipherMissingParam(error)  # pylint: disable=raise-missing-from
    # Add auth to header
    headers["Authorization"] = f"Bearer {auth.token}"
    response: httpx.Response = await client.get(url=url,
                                                params=params)
    json_response = {
        "exec_time": response.elapsed.total_seconds(),
        "headers": response.headers
    }
    return {**json_response, **response.json()}


# TODO: Cannot do as we are talking about hundreds of calls due to the millions of certs stored.
async def ctm_request_list_all(auth: Auth, **kwargs: Any) -> Dict[str,Any]:
    """_summary_

    Args:
        auth (Auth): _description_

    Returns:
        Dict[str,Any]: _description_
    """
    # inital response
    kwargs["params"] = {"limit": 1}
    # refresh for 5 min timer
    auth.gen_refresh_token()
    start_time: float = time.time()
    resp: dict[str,Any] = ctm_request(auth=auth, **kwargs)
    limit: int = 2000
    total: int = resp["total"]
    # set the total amount of iterations required to get full response
    # works when limit is already reached
    iterations: int = int(total/limit) if (total%limit == 0) else (total//limit + 1)
    response: Dict[str,Any] = {
        "exec_time": 0.0,
        "exec_time_start": start_time,
        "exec_time_end": 0.0,
        "exec_time_min": 0.0,
        "exec_time_max": 0.0,
        "exec_time_stdev": 0.0,
        "iterations": copy.deepcopy(iterations),
        "resources": []
    }
    async with httpx.AsyncClient(timeout=360.0,verify=kwargs.get("verify", True)) as client:
        tasks: list[Any] = []
        for number in range(iterations):
            # Set the parameters and increase per run
            kwargs["params"] = {
                "limit": limit,
                "skip": (number*2000+1) if (number != 0) else 0
            }
            kwargs["client"] = client
            tasks.append(asyncio.ensure_future(ctm_request_async(auth=auth,**kwargs)))
        full_listed_resp: List[Dict[str,Any]] = await asyncio.gather(*tasks)
    end_time: float = time.time()
    elapsed_times: list[float] = [value["exec_time"] for value in full_listed_resp]
    # iterations: int = 0
    response["exec_time"] = end_time - start_time
    response["exec_time_end"] = end_time
    response["exec_time_min"] = min(elapsed_times)
    response["exec_time_max"] = max(elapsed_times)
    response["exec_time_stdev"] = statistics.stdev(elapsed_times)
    response["resources"].extend(values["resources"] for values in full_listed_resp)
    return response


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
