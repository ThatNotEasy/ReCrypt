import logging
import coloredlogs
from colorama import Fore, init

init(autoreset=True)

def setup_logging(name: str = "ReCrypt", level: int = logging.DEBUG) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    coloredlogs.install(level=level, logger=logger)
    return logger

def message_info(message, optional_message):
    print(f"{Fore.CYAN}[INFO]: {Fore.WHITE}{message} -{Fore.YELLOW}{optional_message}{Fore.RESET}")
    
def message_success(message, optional_message):
    print(f"{Fore.GREEN}[SUCCESS]: {Fore.WHITE}{message} -{Fore.YELLOW}{optional_message}{Fore.RESET}")
    
def message_error(message):
    print(f"{Fore.RED}[ERROR]: {Fore.WHITE}{message}{Fore.RESET}")