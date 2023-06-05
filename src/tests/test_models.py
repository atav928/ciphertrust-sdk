"""Testing Models"""

from typing import Any, Dict

import unittest

from ciphertrust_sdk.models import AuthParams

SAMPLE: Dict[str,Any] = {
    "hostname": "something.com",
    "grant_type": "password",
    "username": "some-password",
    "headers": {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
}

class TestModels(unittest.TestCase):
    """Testing Dataclass Models"""
    def AuthTest(self) -> None:
        """Test Auth Model"""
        authparam: dict[str, Any] = AuthParams(**SAMPLE)
        self.assertEqual("something.com", authparam.hostname)
        self.assertEqual("password", authparam.grant_type)
