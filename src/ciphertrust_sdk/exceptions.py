"""Exceptions"""


class CipherTrustError(Exception):
    """Generic Cipher Trust Error"""


class CipherAPIError(CipherTrustError):
    """CipherTrust API Error"""


class CipherAuthError(CipherAPIError):
    """CipherTrust Authorization Error"""


class CipherValueError(CipherTrustError):
    """CipherTrust Invalid Value"""


class CipherMissingParam(CipherTrustError):
    """Missing Parameter"""


class CipherPermission(CipherAPIError):
    """Permission Error"""
