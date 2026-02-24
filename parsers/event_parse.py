"""
Docstring for event_parser.py
parses the file collected from windows event logs
"""
from Evtx.Evtx import Evtx
from pathlib import Path
import xmltodict
import json
import os
from pathlib import Path
import time
import logging
from datetime import datetime
import sys
from tqdm import tqdm 

#loggin

logging.basicConfig(
    level=logging.DEBUG,  # minimum level to show
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.getLogger("Evtx").setLevel(logging.WARNING)

def file_path():
    base_dir = Path(__file__).resolve().parent
    path = base_dir.parent / "collector" / "Logs" / "security.evtx"
    return path

path = file_path()
#path = r"/Users/sonnybowers/Documents/University/Group Project/AFTT/main/Automated-forensic-triage-tool/collector/Logs/security.evtx"

def main(path):
    logging.debug("Loading Windows Security Event Log")
    Artifact_count=0  
    Failed_count=0
    with Evtx(path) as log, open("Security_failed_logins.json", "w", encoding="utf-8") as f:
        logging.debug("Converting Event Log Into JSON Dictionay\n")   
        for record in log.records():
            print(f"\rArtifacts Processed: {Artifact_count}", end="", flush=True)
            #logging.info(f"Artifact:{Artifact_count} Processing")
            Artifact_count+=1
            xml_str = record.xml()

            # Convert XML string to Python dict
            event_dict = xmltodict.parse(xml_str)
            #filter the dictionary for needed fields
            # Save each events that matched event id 4625 as JSON in new line

            event_id = event_dict["Event"]["System"]["EventID"]["#text"]
            
            if event_id == "4625":
                filtered = {
                "EventID": event_dict["Event"]["System"]["EventID"]["#text"],
                "TimeCreated": event_dict["Event"]["System"]["TimeCreated"]["@SystemTime"],
                }

                f.write(json.dumps(filtered) + "\n")
                logging.debug(f"Failed Loggin Attempt:\n{filtered}")

                data_list = event_dict["Event"]["EventData"]["Data"]

                if data_list != None:
                    print("Account:" + data_list[5]["#text"] + "\n")

                Failed_count+=1        

    print(f"\n\nTotal Artifacts Found:{Artifact_count}")
    print(f"Failed Loggins Found:{Failed_count}")



if __name__ == "__main__":
    print('')
    start = time.time()
    main(path)
    end = time.time()
    print(f"Time Taken: {round(end - start, 3)} sec")
 

   




