"""
sets up logging format used in the python scripts
"""
#imports
import logging
#styling
from rich.logging import RichHandler


def log_setup(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    logging.getLogger("Evtx").setLevel(logging.WARNING)

