"""
Docstring for collector.event_logs
collects windows events logs for to later parse (Event ID 4625) 
"""

import subprocess
from pathlib import Path
import logging

logging.basicConfig(
    level=logging.DEBUG,  # minimum level to show
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def file_path():
    base_dir = Path("Logs/security.evtx")
    path = base_dir.resolve()
    return path

# run 'wevtutil' shell command with current location to export security logs

def wev_run(path):
    logging.debug("Extracting 'security.evtx' from Event Logs")
    subprocess.run(
        ["wevtutil", "epl", "Security", str(path)],
        check=True
    )

def main():
    path = file_path()
    print(path)
    wev_run(path)
    logging.debug(f"Complete Extraction - stored in: {path}")


if __name__ == "__main__":
    main()