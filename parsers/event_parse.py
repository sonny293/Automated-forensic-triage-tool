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

def file_path():
    base_dir = Path(__file__).resolve().parent
    path = base_dir.parent / "collector" / "Logs" / "security.evtx"
    return path

path = file_path()
#path = r"/Users/sonnybowers/Documents/University/Group Project/AFTT/main/Automated-forensic-triage-tool/collector/Logs/security.evtx"

def main(path):
    with Evtx(path) as log, open("Security_failed_logins.json", "w", encoding="utf-8") as f:
        count=0
        for record in log.records():
            xml_str = record.xml()
            # Convert XML string to Python dict
            event_dict = xmltodict.parse(xml_str)
            #filter the dictionary for needed fields

            for event in event_dict :
                filtered = {
                "EventID": event_dict["Event"]["System"]["EventID"]["#text"],
                "TimeCreated": event_dict["Event"]["System"]["TimeCreated"]["@SystemTime"],
                #"EventData": event_dict["Event"]["EventData"]["Data"][1].get["#text"],
                }
            # Save each events that matched event id 4625 as JSON in new line
            event_id = event_dict["Event"]["System"]["EventID"]["#text"]
            if event_id == "4625":
                print('Failed Login Attempt:')
                f.write(json.dumps(filtered) + "\n")
                print(filtered)
                count+=1          
    print(f"Artifacts Found:{count}")
    return event_dict



if __name__ == "__main__":
    print('')
    event_dict = main(path)
    data_list = event_dict["Event"]["EventData"]["Data"]
    for event in data_list:
        print(data_list[1]["#text"])
   




