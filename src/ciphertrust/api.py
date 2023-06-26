# pylint: disable=too-few-public-methods,missing-class-docstring
"""API"""

from typing import Any, Dict
import orjson

from ciphertrust import config
from ciphertrust.auth import Auth
from ciphertrust.requestapi import (ctm_request, asyn_get_all)
from ciphertrust.static import ENCODE


class API:
    """CipherTrust Manager API"""

    def __init__(self, **kwargs: Any):
        self.auth = Auth(**kwargs)

        # Bind API method classes to this object
        subclasses: dict[str, Any] = self._subclass_container()
        self.get = subclasses["get"]()
        self.post = subclasses["post"]()
        self.patch = subclasses["patch"]()
        self.delete = subclasses["delete"]()

    def _subclass_container(self) -> dict[str,Any]:
        _parent_class = self
        return_object: dict[str,Any] = {}

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

    def convert_to_string(self, query: dict[str,Any]) -> str:
        """convert json to string

        :param query: _description_
        :type query: dict
        :return: _description_
        :rtype: str
        """
        return orjson.dumps(query).decode(ENCODE)  # pylint: disable=no-member


class Get:
    """Calls generic GET requests from CipherTrust Manager

    :return: _description_
    :rtype: _type_
    """
    _parent_class = None
    method = "GET"

    def call(self, url_path: str, **kwargs: Any) -> dict[str, Any]:
        """Generic Call Method

        :param url_path: _description_
        :type url_path: str
        :return: _description_
        :rtype: dict[str, Any]
        """
        url: str = config.API_URL.format(self._parent_class.auth.hostname, # type: ignore
                                         url_path)
        params: dict[str,Any] = kwargs.pop("params", {})
        calls = {
            "standard": ctm_request,
            "list_all": asyn_get_all
        }
        get_all = "list_all" if kwargs.get("get_all", False) else "standard"
        response: dict[str,Any] = calls[get_all](auth=self._parent_class.auth, # type: ignore
                                                 url=url,
                                                 method=self.method, # type: ignore
                                                 params=params,
                                                 timeout=self._parent_class.auth.timeout, # type: ignore
                                                 verify=self._parent_class.auth.verify) # type: ignore
        return response


class Post:
    """Calls generic POST requests for CipherTrust Manager

    :return: _description_
    :rtype: _type_
    """
    _parent_class = None
    method: str = "POST"

    def call(self, url_path: str, **kwargs: Any) -> Dict[str, Any]:
        """POST call for CipherTrust Manager

        :param url_path: _description_
        :type url_path: str
        """
        url: str = config.API_URL.format(self._parent_class.auth.hostname, url_path) # type: ignore
        params: dict[str,Any] = kwargs.pop("params", {})
        data: str = self._parent_class.convert_to_string( # type: ignore
            query=kwargs.pop("query")) if kwargs.get("query") else ""
        response: dict[str, Any] = ctm_request(auth=self._parent_class.auth, # type: ignore
                                               method=self.method,
                                               url=url,
                                               params=params,
                                               data=data,
                                               timeout=self._parent_class.auth.timeout,
                                               verify=self._parent_class.auth.verify)
        return response


class Delete:
    """DELETE API Calls"""
    _parent_class = None
    method: str = "DELETE"

    def call(self, url_path: str, **kwargs: Any) -> dict[str, Any]:
        """DELETE call for CipherTrust Manager

        :param url_path: _description_
        :type url_path: str
        :return: _description_
        :rtype: dict[str, Any]
        """
        url: str = config.API_URL.format(self._parent_class.auth.hostname, url_path)
        response: dict[str, Any] = ctm_request(auth=self._parent_class.auth,
                                               url=url,
                                               method=self.method,
                                               timeout=self._parent_class.auth.timeout,
                                               verify=self._parent_class.auth.verify)
        # print(f"{response=}")
        return response


class Patch:
    _parent_class = None
    method: str = "PATCH"

    def call(self, url_path: str, **kwargs: Any) -> Dict[str, Any]:
        """CipherTrust API Patch calls

        :param url_path: _description_
        :type url_path: _type_
        :return: _description_
        :rtype: Dict[str,Any]
        """
        url: str = config.API_URL.format(self._parent_class.auth.hostname, url_path)
        params: dict = kwargs.pop("params", {})
        data: str = self._parent_class.convert_to_string(
            query=kwargs.pop("query")) if kwargs.get("query") else ""
        response: dict[str, Any] = ctm_request(auth=self._parent_class.auth,
                                               url=url,
                                               method=self.method,
                                               params=params,
                                               data=data,
                                               timeout=self._parent_class.auth.timeout,
                                               verify=self._parent_class.auth.verify)
        # print(f"{response=}")
        return response
