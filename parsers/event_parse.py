"""
Docstring for event_parser.py
parses the file collected from windows event logs
"""
from Evtx.Evtx import Evtx
from pathlib import Path
import xmltodict
import json

#path = r"/Users/sonnybowers/Documents/University/Group Project/AFTT/main/Automated-forensic-triage-tool/collector/Logs/security.evtx"
path = r"Automated-forensic-triage-tool/collector/Logs/security.evtx"
with Evtx(path) as log, open("Security_lines.json", "w", encoding="utf-8") as f:
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
            #"EventData": event_dict["Event"]["EventData"]["Data"],
            }
        # Save each events that matched event id 4625 as JSON in new line
        event_id = event_dict["Event"]["System"]["EventID"]["#text"]
        if event_id == "4625":
            print('Failed Login Attempt:')
            f.write(json.dumps(filtered) + "\n")
            print(filtered)
            count+=1

print(f"Artifacts Found:{count}")


#print(json.dumps(event_dict, indent=2))


if __name__ == "__main__":
    print('')
