import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(
    log_path="logs/sentinel.log",
    level=logging.INFO,
):
    # Configure Sentinel's application log file
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("sentinel")
    logger.setLevel(level)
    logger.propagate = False

    # Remove existing handlers to avoid duplicate log entries.
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    # Rotate the file when it reaches approximately 1 MB.
    file_handler = RotatingFileHandler(
        path,
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    logger.addHandler(file_handler)

    return logger
