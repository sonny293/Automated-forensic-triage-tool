"""
collects windows events logs for to later parse (Event ID 4625) 

inputs:
path - folder to save the extracted security.evtx file
"""

#imports
import subprocess
from pathlib import Path
import logging

logging.basicConfig(
    level=logging.DEBUG,  # minimum level to show
    format="%(asctime)s - %(levelname)s - %(message)s"
)

#dynamicaly finds folder to story event logs
def file_path():
    base_dir = Path("Logs/security.evtx")
    try:
        path = base_dir.resolve()
    except Exception as error:
        logging.error(f'Error occured:{error}') 
        exit()
    else:
        return path   

# run 'wevtutil' shell command with current location to export security logs
def wev_run(path):
    try:
        #runs wevutil - windows tool for exporting event logs
        subprocess.run(
            ["wevtutil", "epl", "Security", str(path)],
            check=True
        )
        logging.debug("Attempting extraction of 'security.evtx' from Windows Event Logs")
        logging.debug(f"Complete Extraction - \nstored in: {path}")
    except FileNotFoundError as e:   
        logging.error("%s", e)
        logging.error("%s", "[HINT] - 'wevutil can only be run on windows") 
    except Exception as error:
        logging.error(error)
        exit()

def main():
    path = file_path()
    wev_run(path)


if __name__ == "__main__":
    main()