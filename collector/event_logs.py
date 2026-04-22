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
    while True:
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
        except PermissionError as e:
            logging.error("%s", e)
            logging.error("%s", "[HINT] - Run the program with higher privileges")
        except FileExistsError as e:
            logging.error("%s", e)
            logging.error("%s", "[HINT] - Security.evtx already exists in '/collector/Logs'")
            pass
        except Exception as error:
            logging.error(error)
            logging.error("%s", "[HINT] - Make sure you run the program with enough privileges")   
        
            logging.info("%s", "if you are running the program for a second time enter ('r') or ('q')")
            rerun = input("Enter: ")
            if rerun.lower() == 'r':
                subprocess.run(
                ["rm", "collector\Logs\security.evtx"],
                check=True)
                pass
            else:
                exit() 

def main():
    evtx_file = file_path()
    wev_run(evtx_file)


if __name__ == "__main__":
    main()