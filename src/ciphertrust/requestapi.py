"""Request API"""

from typing import Any, Dict, List
import re
import json
import os
import time
import datetime
import statistics
import asyncio
import copy
from functools import reduce
from pathlib import Path
import urllib.parse
from dateutil import parser

import orjson
import httpx
import requests
from requests import HTTPError, Response

from ciphertrust.auth import (Auth, refresh_token)  # type: ignore
from ciphertrust.exceptions import (CipherAPIError, CipherMissingParam)
from ciphertrust.static import (DEFAULT_HEADERS, ENCODE, REGEX_NUM,
                                DEFAULT_LIMITS_OVERRIDE, DEFAULT_TIMEOUT_CONFIG_OVERRIDE)
from ciphertrust.utils import (reformat_exception, concat_resources,  # type: ignore
                               verify_path_exists, return_time)


def format_request(request: Response) -> dict[str, Any]:
    """Reformat request.

    :param response: _description_
    :type response: Response
    :return: _description_
    :rtype: dict[str,Any]
    """
    json_response = {
        "status_code": request.status_code,
        "exec_time_total": request.elapsed.total_seconds(),
        "headers": json.loads(orjson.dumps(request.headers.__dict__["_store"]).decode(ENCODE)),  # pylint: disable=no-member
        "exec_time_end": return_time()
    }
    return json_response


def standard_request(request: Response) -> dict[str, Any]:
    """Call standard Request.

    :return: Adjusted Request Response
    :rtype: dict[str,Any]
    """
    req: dict[str, Any] = {**request.json(), **format_request(request)}
    return req


def delete_request(request: Response) -> dict[str, Any]:
    """Deleteed request response.

    :param request: _description_
    :type request: Response
    :return: _description_
    :rtype: dict[str,Any]
    """
    ident: str = urllib.parse.urlparse(request.url).path.split('/')[-1]
    value_type: str = re.sub(REGEX_NUM, "", urllib.parse.urlparse(request.url).path.split('/')[-2])
    delete_response: dict[str, Any] = {
        "id": ident,
        "message": f"Deleted {value_type} with ID {ident}"
    }
    req: dict[str, Any] = {**delete_response, **format_request(request)}
    return req


def download_request(request: Response, **kwargs: Any) -> dict[str, Any]:
    """Use to Download Tar files. Only supports tar.gz can update.

    :return: Adjusted Request Ressponse
    :rtype: dict[str,Any]
    """
    chunk_size: int = kwargs.pop("chunk_size", 128)
    save_path: str = kwargs.pop("save_dir", os.path.expanduser('~'))
    if not verify_path_exists(path_dir=save_path):
        raise FileExistsError(f"{save_path} does not exist")
    parsed_url: urllib.parse.ParseResult = urllib.parse.urlparse(request.url)  # type: ignore
    save_filename: Path = Path.joinpath(
        Path(save_path) /
        f"{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}_ciphertrust_log_{parsed_url.hostname}.tar.gz")  # pylint: disable=line-too-long,unknown-option-value
    with open(save_filename, 'wb') as fild:
        for chunk in request.iter_content(chunk_size=chunk_size):
            fild.write(chunk)
    response: dict[str, str] = {
        "message": "downloaded system logs completed",
        "location": str(save_filename)
    }
    response = {**response, **format_request(request)}
    return response


@refresh_token
def ctm_request(auth: Auth, **kwargs: Any) -> Response:  # pylint: disable=too-many-locals
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
    kwargs.get("headers", {}).update({"Authorization": f"Bearer {auth.token}"})
    response: Response = requests.request(**kwargs)  # pylint: disable=missing-timeout
    api_raise_error(response=response)
    return response


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
        "exec_time_total": response.elapsed.total_seconds(),
        "headers": json.loads(orjson.dumps(response.headers.__dict__["_store"]).decode(ENCODE)),  # pylint: disable=no-member
        "exec_time_end": return_time()
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
    start_time: str = return_time()
    resp: dict[str, Any] = ctm_request(auth=auth, **kwargs)
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
                                             iterations=send_iterations,  # type: ignore
                                             limit=limit,  # type: ignore
                                             **kwargs)
        full_listed_resp: Any = full_listed_resp + tmp_listed_resp
        iterations -= 10
        # print(f"One loop iteration completed new_iterations={iterations}")
    response = {**response, **build_responsde(full_listed_resp=full_listed_resp)}  # type: ignore
    response["exec_time_total"] = (parser.isoparse(response["exec_time_end"]) - parser.isoparse(start_time)).total_seconds()
    response["exec_time_start"] = start_time
    return response


@refresh_token
async def split_up_req(auth: Auth,
                       iterations: int,
                       limit: int,
                       **kwargs: Any) -> List[Dict[str, Any]]:
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
            # print(f"{number=}|{kwargs=}")
            tasks.append(asyncio.ensure_future(ctm_request_async(auth=auth, **kwargs)))
        full_listed_resp: List[Dict[str, Any]] = await asyncio.gather(*tasks)  # type: ignore
    return full_listed_resp  # type: ignore
    # print(f"{full_listed_resp=}")


def build_responsde(full_listed_resp: list[dict[str, Any]]) -> dict[str, Any]:
    """Build Returned Reponse with statistics.

    :param full_listed_resp: _description_
    :type full_listed_resp: list[dict[str, Any]]
    :return: _description_
    :rtype: dict[str, Any]
    """
    response: Dict[str, Any] = {
        "exec_time_end": 0.0,
        "exec_time_min": 0.0,
        "exec_time_max": 0.0,
        "exec_time_stdev": 0.0,
        "resources": []
    }
    end_time: float = time.time()
    elapsed_times: list[float] = [value["exec_time_total"] for value in full_listed_resp]
    response["elapsed_times"] = elapsed_times
    response["exec_time_end"] = end_time
    response["exec_time_min"] = min(elapsed_times)
    response["exec_time_max"] = max(elapsed_times)
    response["exec_time_stdev"] = statistics.stdev(elapsed_times)
    response["resources"] = reduce(concat_resources, full_listed_resp)["resources"]  # type: ignore
    return response


def asyn_get_all(auth: Auth, **kwargs: Any) -> dict[str, Any]:
    """Asyncio get All. Still under eval

    :param auth: _description_
    :type auth: Auth
    :return: _description_
    :rtype: dict[str, Any]
    """
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
