# pylint: disable=too-few-public-methods,missing-class-docstring
"""CipherTrust API"""

from typing import Any, Dict
import orjson
from requests import Response

from ciphertrust import config
from ciphertrust.utils import return_epoch
from ciphertrust.models import RequestParams
from ciphertrust.auth import Auth
from ciphertrust.requestapi import (api_raise_error, ctm_request)
from ciphertrust.static import ENCODE


class API:
    """
    CipherTrust Manager API.
    """

    _ctm_kwargs: dict[str, Any] = {}

    def __init__(self, **kwargs: Any) -> None:
        """Generate API to call to CipherTrust Manager."""
        self.auth = Auth(**kwargs)
        # Bind API method classes to this object
        subclasses: dict[str, Any] = self._subclass_container()
        self.get: Any = subclasses["get"]()
        self.post: Any = subclasses["post"]()
        self.patch: Any = subclasses["patch"]()
        self.delete: Any = subclasses["delete"]()

    def _subclass_container(self) -> dict[str, Any]:
        _parent_class: Any = self
        return_object: dict[str, Any] = {}

        class GetWrapper(Get):
            def __init__(self) -> None:
                self._parent_class = _parent_class
        return_object["get"] = GetWrapper

        class PostWrapper(Post):
            def __init__(self) -> None:
                self._parent_class = _parent_class
        return_object["post"] = PostWrapper

        class PatchWrapper(Patch):
            def __init__(self) -> None:
                self._parent_class = _parent_class
        return_object["patch"] = PatchWrapper

        class DeleteWrapper(Delete):
            def __init__(self) -> None:
                self._parent_class = _parent_class
        return_object["delete"] = DeleteWrapper
        return return_object

    def convert_to_string(self, query: dict[str, Any]) -> str:
        """
        Convert json to string.

        :param query: _description_
        :type query: dict
        :return: _description_
        :rtype: str
        """
        return orjson.dumps(query).decode(ENCODE)  # pylint: disable=no-member


class Get:
    """
    Calls generic GET requests from CipherTrust Manager.

    :return: _description_
    :rtype: _type_
    """

    _parent_class = None
    _response: Response
    method: str = "GET"

    def call(self, url_path: str, **kwargs: Any) -> dict[str, Any]:
        """Call Method for GET Requests.

        :param url_path: _description_
        :type url_path: str
        :return: _description_
        :rtype: dict[str, Any]
        """
        url: str = config.API_URL.format(self._parent_class.auth.hostname, url_path)  # type: ignore
        save_dir = kwargs.pop("save_dir", "")
        ctm_get_kwargs: dict[str, Any] = RequestParams.create_from_kwargs(
            method=self.method,
            url=url,
            verify=self._parent_class.auth.verify,  # type: ignore
            timeout=self._parent_class.auth.timeout,  # type: ignore
            **kwargs).asdict()
        start_time: float = return_epoch()
        req: Response = ctm_request(auth=self._parent_class.auth, **ctm_get_kwargs)  # type: ignore
        self._response = req
        if save_dir:
            response = api_raise_error(response=req, save_dir=save_dir,
                                       start_time=start_time,  **ctm_get_kwargs)
            return response
        response = api_raise_error(response=req, method_type="standard",
                                   start_time=start_time, **ctm_get_kwargs)
        return response

    @property
    def response(self) -> Response:
        return self._response

    @response.setter
    def response(self, value: Response) -> None:
        self._response = value

    def return_response(self) -> Response:
        return self._response


class Post:
    """
    Calls generic POST requests for CipherTrust Manager.

    :return: _description_
    :rtype: _type_
    """

    _parent_class = None
    _response: Response
    method: str = "POST"

    def call(self, url_path: str, **kwargs: Any) -> Dict[str, Any]:
        """
        POST call for CipherTrust Manager.

        :param url_path: _description_
        :type url_path: str
        """
        url: str = config.API_URL.format(self._parent_class.auth.hostname, url_path)  # type: ignore
        ctm_post_kwargs: dict[str, Any] = RequestParams.create_from_kwargs(
            url=url,
            method=self.method,
            verify=self._parent_class.auth.verify,  # type: ignore
            timeout=self._parent_class.auth.timeout,  # type: ignore
            **kwargs).asdict()
        start_time: float = return_epoch()
        req: Response = ctm_request(auth=self._parent_class.auth, **ctm_post_kwargs)  # type:ignore
        self._response = req
        return api_raise_error(
            response=req, method_type="standard", start_time=start_time, **ctm_post_kwargs)

    @property
    def response(self) -> Response:
        return self._response

    @response.setter
    def response(self, value: Response) -> None:
        self._response = value

    def return_response(self) -> Response:
        return self._response


class Delete:
    """
    Request method DELETE.

    :return: _description_
    :rtype: _type_
    """
    _parent_class = None
    _response: Response
    method: str = "DELETE"

    def call(self, url_path: str, **kwargs: Any) -> dict[str, Any]:
        """DELETE call for CipherTrust Manager

        :param url_path: _description_
        :type url_path: str
        :return: _description_
        :rtype: dict[str, Any]
        """
        url: str = config.API_URL.format(self._parent_class.auth.hostname, url_path)  # type: ignore
        ctm_delete_kwargs: dict[str, Any] = RequestParams.create_from_kwargs(
            url=url,
            method=self.method,
            timeout=self._parent_class.auth.timeout,  # type: ignore
            verify=self._parent_class.auth.verify,  # type: ignore
            **kwargs).asdict()
        start_time: float = return_epoch()
        # Returns Status Code 204 without any content
        req: Response = ctm_request(auth=self._parent_class.auth, **ctm_delete_kwargs)  # type:ignore
        self._response = req
        return api_raise_error(
            response=req, method_type="delete", start_time=start_time, **ctm_delete_kwargs)

    @property
    def response(self) -> Response:
        return self._response

    @response.setter
    def response(self, value: Response) -> None:
        self._response = value

    def return_response(self) -> Response:
        return self._response


class Patch:
    """
    Request method PATCH.

    :return: _description_
    :rtype: _type_
    """
    _parent_class = None
    _response: Response
    method: str = "PATCH"

    def call(self, url_path: str, **kwargs: Any) -> Dict[str, Any]:
        """
        CipherTrust API Patch calls.

        :param url_path: _description_
        :type url_path: _type_
        :return: _description_
        :rtype: Dict[str,Any]
        """

        url: str = config.API_URL.format(self._parent_class.auth.hostname, url_path)  # type: ignore
        ctm_patch_kwargs: dict[str, Any] = RequestParams.create_from_kwargs(
            url=url,
            method=self.method,
            timeout=self._parent_class.auth.timeout,  # type: ignore
            verify=self._parent_class.auth.verify,  # type: ignore
            **kwargs).asdict()
        start_time: float = return_epoch()
        req: Response = ctm_request(auth=self._parent_class.auth, **ctm_patch_kwargs)  # type:ignore
        self._response = req
        return api_raise_error(
            response=req, method_type="standard", start_time=start_time, **ctm_patch_kwargs)

    @property
    def response(self) -> Response:
        return self._response

    @response.setter
    def response(self, value: Response) -> None:
        self._response = value

    def return_response(self) -> Response:
        return self._response
