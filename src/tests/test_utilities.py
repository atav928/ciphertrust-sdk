"""Testing Utilities"""

from typing import Any

import unittest

from ciphertrust_sdk import utils

DOMAIN_TESTS_VALID: list[str] = [
    "some.url.domain.com",
    "some-other-domain.edu",
    "top.sub.domain.com",
    "domain.com"
]

DOMAIN_TESTS_INVALID: list[Any] = [
    "invalid_domain*.com",
    12345,
    "invalid",
    "*not)(valid)"
]


class TestUtilities(unittest.TestCase):
    """Testing CipherTrust Utilities"""

    def test_validators_true(self) -> None:
        """Validating Domain List that should always be True
        """
        for value in DOMAIN_TESTS_VALID:
            result: bool = utils.validate_domain(value)
            print(f"{value} is {result}")
            self.assertTrue(result)

    def test_validators_false(self) -> None:
        """Validating Domain Lists that shoudl always be False"""
        for value in DOMAIN_TESTS_INVALID:
            result: bool = utils.validate_domain(value)
            print(f"{value} is {result}")
            self.assertFalse(result)
