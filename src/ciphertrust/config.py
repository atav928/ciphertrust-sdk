"""Configurations"""

import tempfile
from pathlib import Path
import platform

CONFIG_LOCATION: list[str] = [
    str(Path.joinpath(Path.home() / ".config/ciphertrust-sdk.yaml")),
    str(Path('/etc/ciphertrust-sdk.yaml'))
]

def get_config_location() -> str:
    """Retrieve configuration location if one exists.

    :return: _description_
    :rtype: str
    """
    for location in CONFIG_LOCATION:
        if Path.is_file(Path(location)):
            return location
    return ""

def get_log_dir() -> str:
    """Get default log directory depending on OS.

    :return: _description_
    :rtype: _type_
    """
    directory: dict[str,Path] = {
        "darwin": Path.joinpath(Path.home() / "Library/Logs"),
        "linux": Path("/var/log")
    }
    plat: str = platform.system()
    try:
        return str(directory[plat.lower()])
    except KeyError:
        return tempfile.gettempdir()

class Configs:
    AUTH: str = "https://{}/api/v1/auth/tokens"
    API_URL: str = "https://{}/api/v1/{}"
    ENDPOINT_KEYS: str = "https://{}/api/vault/keys2/"
    ENDPOINT_KEYS_QUERY: str = "https://{}/api/vault/query-keys/"
    # Standard logging can be changed with importing a yaml config
    LOGDIR: str = get_log_dir()
    LOGSTREAM: bool = True
    LOGSET: bool = True
    LOGNAME: str = "ciphertrust_sdk.log"
    LOGFILE: bool = False
    LOGLEVEL: str = "INFO"
    LOGMAXBYTES: int = 5242990
    LOGBACKUPCOUNT: int = 10
    YAML_CONFIG = get_config_location()
