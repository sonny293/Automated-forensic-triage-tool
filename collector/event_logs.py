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
    base_dir = Path("collector/Logs/security.evtx")
    try:
        evtx_file = base_dir.resolve()
    except Exception as error:
        logging.error(f'Error occured:{error}') 
        exit()
    else:
        return evtx_file  

# run 'wevtutil' shell command with current location to export security logs
def wev_run(evtx_file):
    try:
        #runs wevutil - windows tool for exporting event logs
        subprocess.run(
            ["wevtutil", "epl", "Security", str(evtx_file)],
            check=True
        )
        logging.debug("Attempting extraction of 'security.evtx' from Windows Event Logs")
        logging.debug(f"Complete Extraction - \nstored in: {evtx_file}")
    except FileNotFoundError as e:   
        logging.error("%s", e)
        logging.error("%s", "[HINT] - 'wevutil can only be run on windows")
    except FileExistsError as e:
        logging.error("%s", e)
        logging.error("%s", "[HINT] - Security.evtx already exists in '/collector/Logs'")
        break
    except Exception as error:
        logging.error(error)
        exit()

def main():
    evtx_file = file_path()
    wev_run(evtx_file)


if __name__ == "__main__":
    main()