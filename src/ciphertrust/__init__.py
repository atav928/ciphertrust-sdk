"""Package Initialization"""

import yaml

import easy_logger

from ciphertrust._version import __version__
from ciphertrust.config import Configs

config = Configs()

if config.YAML_CONFIG:
    with open(config.YAML_CONFIG, 'r', encoding="utf-8") as yam:
        yaml_configs = yaml.safe_load(yam)
    config.LOGDIR = yaml_configs.get("LOGDIR", config.LOGDIR)
    config.LOGSTREAM = yaml_configs.get("LOGSTREAM", config.LOGSTREAM)
    config.LOGSET = yaml_configs.get("LOGSET", config.LOGSET)
    config.LOGNAME = yaml_configs.get("LOGNAME", config.LOGNAME)
    config.LOGFILE = yaml_configs.get("LOGFILE", config.LOGFILE)
    config.LOGLEVEL = yaml_configs.get("LOGLEVEL", config.LOGLEVEL)
    config.LOGMAXBYTES = yaml_configs.get("LOGMAXBYTES", config.LOGMAXBYTES)
    config.LOGBACKUPCOUNT = yaml_configs.get("LOGBACKUPCOUNT", config.LOGBACKUPCOUNT)

logger = easy_logger.RotatingLog("ciphertrust-sdk",
                                 logName=config.LOGNAME,
                                 logDir=config.LOGDIR,
                                 level=config.LOGLEVEL,
                                 stream=config.LOGSTREAM,
                                 setLog=config.LOGSET,
                                 setFile=config.LOGFILE,
                                 maxBytes=config.LOGMAXBYTES,
                                 backupCount=config.LOGBACKUPCOUNT)
