import logging
import os


logger = None

def setup_logging():
    """
    Setup logging configuration
    :return: logger
    """
    # create logger
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(log_level)

    # create formatter
    formatter = logging.Formatter("[%(levelname)s] - %(message)s")

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    # Avoid duplicates in AWS CloudWatch
    logger.propagate = False

    return logger

def get_logger():
    """
    Returns logger
    :return: logger
    """
    return logger


logger = setup_logging()

