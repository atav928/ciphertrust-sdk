"""Package Initialization"""


import yaml

from ciphertrust._version import __version__
from ciphertrust.config import Configs

config = Configs()

if config.YAML_CONFIG:
    with open(config.YAML_CONFIG, "r", encoding="utf-8") as yam:
        yaml_configs = yaml.safe_load(yam)
    config.LOGDIR = yaml_configs.get("LOGDIR", config.LOGDIR)
    config.LOGSTREAM = yaml_configs.get("LOGSTREAM", config.LOGSTREAM)
    config.LOGSET = yaml_configs.get("LOGSET", config.LOGSET)
    config.LOGNAME = yaml_configs.get("LOGNAME", config.LOGNAME)
    config.LOGFILE = yaml_configs.get("LOGFILE", config.LOGFILE)
    config.LOGLEVEL = yaml_configs.get("LOGLEVEL", config.LOGLEVEL)
    config.LOGMAXBYTES = yaml_configs.get("LOGMAXBYTES", config.LOGMAXBYTES)
    config.LOGBACKUPCOUNT = yaml_configs.get("LOGBACKUPCOUNT", config.LOGBACKUPCOUNT)

try:
    import easy_logger
    logging = easy_logger.RotatingLog(
        "ciphertrust-sdk",
        logName=config.LOGNAME,
        logDir=config.LOGDIR,
        level=config.LOGLEVEL,
        stream=config.LOGSTREAM,
        setLog=config.LOGSET,
        setFile=config.LOGFILE,
        maxBytes=config.LOGMAXBYTES,
        backupCount=config.LOGBACKUPCOUNT,
    )
    logging.getLogger(__name__).info(f'msg="Initiated rotate logger."|logName={config.LOGNAME}, logDir={config.LOGDIR}')
except (PermissionError, ImportError) as error:
    import logging
    logging.getLogger(__name__).error(f'Unable to import Easy Lgger or set up log"|error={str(error)}')

__all__ = [
    "logging",

]