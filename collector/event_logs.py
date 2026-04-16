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
    try:
        path = base_dir.resolve()
    except Exception as error:
        print(f'Error occured:{error}') 
        exit()
    else:
        return path   

# run 'wevtutil' shell command with current location to export security logs

def wev_run(path):
    try:
        logging.debug("Extracting 'security.evtx' from Event Logs")
        subprocess.run(
            ["wevtutil", "epl", "Security", str(path)],
            check=True
        )
        logging.debug(f"Complete Extraction - \nstored in: {path}")
    except Exception as error:
        print(f'Error occured:{error}')
        exit()

def main():
    path = file_path()
    wev_run(path)


if __name__ == "__main__":
    main()