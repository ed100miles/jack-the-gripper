import json
from logging import config, getLogger
from pathlib import Path


config_file = Path(__file__).parent / "log_config.json"

with open(config_file) as file:
    log_config = json.load(file)

config.dictConfig(config=log_config)
logger = getLogger("jacks_logger")
