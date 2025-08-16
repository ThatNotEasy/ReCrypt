import logging
import coloredlogs
from colorama import Fore, init
from datetime import datetime

init(autoreset=True)

def setup_logging(name: str = "ReCrypt", level: int = logging.DEBUG) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        fmt = "[%(name)s] - [%(asctime)s] [%(levelname)s] : %(message)s"
        datefmt = "%Y-%m-%d %H:%M:%S"
        coloredlogs.install(
            level=level,
            logger=logger,
            fmt=fmt,
            datefmt=datefmt
        )
    return logger

log = setup_logging()

def message_info(message, optional_message=""):
    log.info(f"{message} - {Fore.YELLOW}{optional_message}{Fore.RESET}")
