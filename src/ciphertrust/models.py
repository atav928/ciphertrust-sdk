"""Models"""

import copy
from typing import Dict, List, Any, Optional, cast

from dataclasses import dataclass, field

from ciphertrust.static import DEFAULT_HEADERS, VALUES
from ciphertrust.exceptions import CipherValueError
from ciphertrust.utils import validate_domain

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
    timeout: int = 60
    headers: Dict[str, Any] = default_field(DEFAULT_HEADERS)
    expiration: Optional[int] = NONETYPE

    def __post_init__(self) -> None:
        """Verify correct values for: 'grant_type', 'hostname', 'verify'"""
        if self.grant_type not in VALUES:
            raise CipherValueError(f"Invalid grant type: {self.grant_type=}")
        if not any([isinstance(self.verify, bool), isinstance(self.verify, str)]):
            raise CipherValueError(f"Invalid value: {self.verify=}")
        # TODO: Verify hostname is a valid domainname
        if not validate_domain(self.hostname):
            raise CipherValueError(f"Invlalid hostname: {self.hostname}")

    def __new__(cls, *args, **kwargs):  # pylint: disable=unused-arguments
        """Used to remove any unwatned arguments

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


if __name__ == "__main__":
    sample: Dict[str, Any] = {
        "hostname": "something.com",
        "grant_type": "password",
        "username": "some-password",
        "headers": {
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        "ext": "value"
    }
    authparam: dict[str, Any] = AuthParams(**sample).asdict()
    # print(f"{authparam=}")
