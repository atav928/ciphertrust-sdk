"""Request API"""

from typing import Any, Dict, List
import time
import statistics
import asyncio
import copy
from functools import reduce

import orjson
import httpx
import requests
from requests import HTTPError, Response

from ciphertrust.auth import (Auth, refresh_token)
from ciphertrust.exceptions import (CipherAPIError, CipherMissingParam)
from ciphertrust.static import (DEFAULT_HEADERS, ENCODE,
                                DEFAULT_LIMITS_OVERRIDE, DEFAULT_TIMEOUT_CONFIG_OVERRIDE)
from ciphertrust.utils import (reformat_exception, concat_resources)


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
    # auth = refresh_token(auth=auth)
    headers["Authorization"] = f"Bearer {auth.token}"
    response: httpx.Response = await client.get(url=url,
                                                params=params,
                                                headers=headers)
    json_response = {
        "exec_time": response.elapsed.total_seconds(),
        "headers": response.headers,
        "exec_time_end": time.time()
    }
    return {**json_response, **response.json()}


# TODO: Cannot do as we are talking about hundreds of calls due to the millions of certs stored.
@refresh_token
async def ctm_request_list_all(auth: Auth, **kwargs: Any) -> Dict[str, Any]:
    """_summary_

    Args:
        auth (Auth): _description_

    Returns:
        Dict[str,Any]: _description_
    """
    # inital response
    kwargs["params"] = {"limit": 1}
    # refresh for 5 min timer
    # auth.gen_refresh_token()
    # print(f"token_expires={auth.expiration}")
    start_time: float = time.time()
    resp: dict[str, Any] = ctm_request(auth=auth, **kwargs)
    # print(f"{resp=}")
    limit: int = 1000
    total: int = resp["total"]
    # set the total amount of iterations required to get full response
    # works when limit is already reached
    # TODO: This will send full iterations, but too many calls.
    # Reduce the amount of calls to prevent excessive calls.
    iterations: int = int(total/limit) if (total % limit == 0) else (total//limit + 1)
    # iterations = 10
    response: Dict[str, Any] = {
        "total": total,
        "exec_time_start": start_time,
        "iterations": copy.deepcopy(iterations),
    }
    full_listed_resp = []
    while iterations > 0:
        send_iterations = 10 if iterations <= 10 else iterations
        tmp_listed_resp = await split_up_req(auth=auth,
                                             iterations=send_iterations,
                                             limit=limit,
                                             **kwargs)
        full_listed_resp = full_listed_resp + tmp_listed_resp
        iterations -= 10
        print(f"One loop iteration completed new_iterations={iterations}")
    response = {**response, **build_responsde(full_listed_resp=full_listed_resp)}
    response["exec_time"] = response["exec_time_end"] - start_time
    return response


@refresh_token
async def split_up_req(auth: Auth, iterations: int, limit: int, **kwargs) -> List[Dict[str, Any]]:
    """Splitting up requests due to too many being sent and cannot handle.
      Trying to adjust with timeout, but still causes errors on return.

    :param auth: _description_
    :type auth: Auth
    :param iterations: _description_
    :type iterations: int
    :param limit: _description_
    :type limit: int
    :return: _description_
    :rtype: List[Dict[str,Any]]
    """
    async with httpx.AsyncClient(limits=DEFAULT_LIMITS_OVERRIDE,
                                 timeout=DEFAULT_TIMEOUT_CONFIG_OVERRIDE,
                                 verify=kwargs.get("verify", True)) as client:
        tasks: list[Any] = []
        for number in range(iterations):
            # Set the parameters and increase per run
            kwargs["params"] = {
                "limit": limit,
                "skip": (number*limit+1) if (number != 0) else 0
            }
            kwargs["client"] = client
            print(f"{number=}|{kwargs=}")
            tasks.append(asyncio.ensure_future(ctm_request_async(auth=auth, **kwargs)))
        full_listed_resp: List[Dict[str, Any]] = await asyncio.gather(*tasks)
    return full_listed_resp
    # print(f"{full_listed_resp=}")


def build_responsde(full_listed_resp: list[dict[str, Any]]) -> dict[str, Any]:
    response: Dict[str, Any] = {
        "exec_time_end": 0.0,
        "exec_time_min": 0.0,
        "exec_time_max": 0.0,
        "exec_time_stdev": 0.0,
        "resources": []
    }
    end_time: float = time.time()
    elapsed_times: list[float] = [value["exec_time"] for value in full_listed_resp]
    response["elapsed_times"] = elapsed_times
    response["exec_time_end"] = end_time
    response["exec_time_min"] = min(elapsed_times)
    response["exec_time_max"] = max(elapsed_times)
    response["exec_time_stdev"] = statistics.stdev(elapsed_times)
    response["resources"] = reduce(concat_resources, full_listed_resp)["resources"]
    return response


def asyn_get_all(auth: Auth, **kwargs: Any) -> dict[str, Any]:
    return asyncio.run(ctm_request_list_all(auth=auth, **kwargs))


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
