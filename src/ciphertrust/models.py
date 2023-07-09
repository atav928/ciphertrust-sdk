# pylint: disable=line-too-long
"""Models"""

import copy
from typing import Dict, List, Any, Optional, cast

from dataclasses import dataclass, field, fields
import orjson

from ciphertrust.static import (DEFAULT_HEADERS, DEFAULT_TIMEOUT, ENCODE, VALID_METHODS, GRANT_VALUES)
from ciphertrust.exceptions import CipherValueError
from ciphertrust.utils import validate_domain, verify_file_exists

NONETYPE: None = cast(None, object())


def default_field(obj: Dict[str, Any]) -> Any:
    """Dataclass default Object field

    :param obj: dictionary object
    :type obj: Dict[str,Any]
    :return: Dict
    :rtype: Object
    """
    return field(default_factory=lambda: copy.copy(obj))


@dataclass()
class AuthParams:  # pylint: disable=missing-class-docstring,too-many-instance-attributes
    """Authorization Parameters for CipherTrust Auth

    :raises CipherValueError: Invalid parameter supplied
    :return: _description_
    :rtype: _type_
    """
    hostname: str
    connnection: Optional[str] = NONETYPE
    cookies: Optional[bool] = NONETYPE
    domain: Optional[str] = NONETYPE
    grant_type: str = "password"
    labels: List[str] = field(default_factory=lambda: [])
    password: Optional[str] = NONETYPE
    refresh_token: Optional[str] = NONETYPE
    refresh_token_lifetime: Optional[int] = NONETYPE
    refresh_token_revoke_unused_in: Optional[int] = NONETYPE
    renew_refresh_token: bool = False
    username: Optional[str] = NONETYPE
    cert: Optional[Any] = NONETYPE
    verify: Any = True
    timeout: float = DEFAULT_TIMEOUT
    headers: Dict[str, Any] = default_field(DEFAULT_HEADERS)
    expiration: Optional[int] = NONETYPE

    def __post_init__(self) -> None:
        """Verify correct values for: 'grant_type', 'hostname', 'verify'"""
        if self.grant_type not in GRANT_VALUES:
            raise CipherValueError(f"Invalid grant type: {self.grant_type=}")
        if not any([isinstance(self.verify, bool), isinstance(self.verify, str)]):
            raise CipherValueError(f"Invalid value: {self.verify=}")
        # TODO: Verify hostname is a valid domainname
        if not validate_domain(self.hostname):
            raise CipherValueError(f"Invlalid hostname: {self.hostname}")

    def __new__(cls, *args: Any, **kwargs: Any):  # pylint: disable=unused-argument,unknown-option-value
        """Used to append any additional parameters passed.

        :return: _description_
        :rtype: _type_
        """
        try:
            initializer = cls.__initializer
        except AttributeError:
            # Store the original init on the class in a different place
            cls.__initializer = initializer = cls.__init__
            # replace init with something harmless
            cls.__init__ = lambda *a, **k: None
        # code from adapted from Arne
        added_args = {}
        for name in list(kwargs.keys()):
            if name not in cls.__annotations__:  # pylint: disable=no-member
                added_args[name] = kwargs.pop(name)
        ret = object.__new__(cls)
        initializer(ret, **kwargs)
        # ... and add the new ones by hand
        for new_name, new_val in added_args.items():
            setattr(ret, new_name, new_val)
        return ret

    def asdict(self) -> dict[str, Any]:
        """Returns dataclass as dictionary.

        :return: dataclass dictionary
        :rtype: dict[str, Any]
        """
        return {key: value for key, value in self.__dict__.items() if value is not NONETYPE}


@dataclass
class RequestParams:  # pylint: disable=too-many-instance-attributes
    """Request Parameters used for HTTPS Requests.

    :param method: method for the new :class:`Request` object: ``GET``, ``OPTIONS``, ``HEAD``, ``POST``, ``PUT``, ``PATCH``, or ``DELETE``.
    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary, list of tuples or bytes to send
        in the query string for the :class:`Request`.
    :param data: (optional) Dictionary, list of tuples, bytes, or file-like
        object to send in the body of the :class:`Request`.
    :param json: (optional) A JSON serializable Python object to send in the body of the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
    :param cookies: (optional) Dict or CookieJar object to send with the :class:`Request`.
    :param files: (optional) Dictionary of ``'name': file-like-objects`` (or ``{'name': file-tuple}``) for multipart encoding upload.
        ``file-tuple`` can be a 2-tuple ``('filename', fileobj)``, 3-tuple ``('filename', fileobj, 'content_type')``
        or a 4-tuple ``('filename', fileobj, 'content_type', custom_headers)``, where ``'content-type'`` is a string
        defining the content type of the given file and ``custom_headers`` a dict-like object containing additional headers
        to add for the file.
    :param auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
    :param timeout: (optional) How many seconds to wait for the server to send data
        before giving up, as a float, or a :ref:`(connect timeout, read
        timeout) <timeouts>` tuple.
    :type timeout: float or tuple
    :param allow_redirects: (optional) Boolean. Enable/disable 
            GET/OPTIONS/POST/PUT/PATCH/DELETE/HEAD redirection. 
            Defaults to ``True``.
    :type allow_redirects: bool
    :param proxies: (optional) Dictionary mapping protocol to the URL of the proxy.
    :param verify: (optional) Either a boolean, in which case it controls whether we verify
            the server's TLS certificate, or a string, in which case it must be a path
            to a CA bundle to use. Defaults to ``True``.
    :param stream: (optional) if ``False``, the response content will be immediately downloaded.
    :param cert: (optional) if String, path to ssl client cert file (.pem). 
            If Tuple, ('cert', 'key') pair.

    :return: :datclass:`RequestParams <RequestParams>` object
    :rtype: models.RequestParams
    """
    method: str
    url: str
    timeout: Any = DEFAULT_TIMEOUT
    params: Optional[dict[str, Any]] = NONETYPE
    data: Optional[str] = NONETYPE
    json: Optional[dict[str, Any]] = NONETYPE
    headers: Dict[str, Any] = default_field(DEFAULT_HEADERS)
    cookies: Optional[dict[str, Any]] = NONETYPE
    files: Optional[dict[str, Any]] = NONETYPE
    auth: Optional[tuple[str, str]] = NONETYPE
    allow_redirects: Optional[bool] = NONETYPE
    proxies: Optional[dict[str, Any]] = NONETYPE
    verify: Any = True
    stream: bool = False
    cert: Optional[Any] = NONETYPE

    def __post_init__(self) -> None:
        """Post Init functions to run verifications on parameters passed.

        :raises ValueError: _description_
        :raises FileNotFoundError: _description_
        """
        if self.method not in VALID_METHODS:
            raise CipherValueError(f"Invalid method type: {self.method}")
        if all([not isinstance(self.json, dict), self.json is not NONETYPE]):
            raise CipherValueError(f"Invalid request param json: {self.json}")
        if all([isinstance(self.data, str), self.data is not NONETYPE]):
            self.data = orjson.dumps(self.data).decode(ENCODE)  # pylint: disable=no-member
        if not any([isinstance(self.verify, bool), isinstance(self.verify, str)]):
            raise CipherValueError(f"Invalid value: {self.verify=}")
        if isinstance(self.verify, str):
            verify_file_exists(self.verify)

    @classmethod
    def create_from_dict(cls, dict_: dict[str, Any]):
        """Class Method that returns RequestParams dataclass
        using a dictionary and strips invalid params.

        :param dict_: _description_
        :type dict_: _type_
        :return: Dataclass
        :rtype: :dataclass: RequestParams
        """
        class_fields = {f.name for f in fields(cls)}
        return RequestParams(
            **{k: v for k, v in dict_.items() if k in class_fields})

    @classmethod
    def create_from_kwargs(cls, **kwargs: Any):
        """Class method that returns RequestParams dataclass by unpacking paramter values
        and strips out invalid params.

        :param kwargs: unpacked key:value pairs
        :type **kwargs: variable length argument list
        :return: Dataclass
        :rtype: :dataclass: RequestParams
        """
        class_fields = {f.name for f in fields(cls)}
        return RequestParams(
            **{k: v for k, v in kwargs.items() if k in class_fields})

    def asdict(self) -> dict[str, Any]:
        """Returns dataclass as dictionary and removes any none types.

        :return: dataclass dictionary
        :rtype: dict[str, Any]
        """
        return {key: value for key, value in self.__dict__.items() if value is not NONETYPE}


if __name__ == "__main__":
    sample: Dict[str, Any] = {
        "hostname": "something.com",
        "grant_type": "password",
        "username": "some-password",
        "headers": {
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        "ext": "value",
        "expiration_offset": 8.0
    }
    req_sample: dict[str, Any] = {"url": "https://example.com/",
                                  "method": "GET", "verify": False, "invalid_param": "somestring"}
    authparam: dict[str, Any] = AuthParams(**sample).asdict()
    print(f"{authparam=}")
    request_params = RequestParams.create_from_kwargs(**req_sample).asdict()
    print(f"{request_params=}")
