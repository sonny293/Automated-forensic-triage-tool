"""
Parses the .evtx log file and extracts all failed login events (Event ID 4625).

Returns:
filtered_artifacts (dict): IP -> list of datetime timestamps
raw_events        (list):  list of dicts with per-event detail
failed_count      (int):   total number of failed login events found

Parameters
- evtx_path (str): Filesystem path to the .evtx event log file to read.
- attempts_output_path (str): Path to SON output file. which contains failed logon event.

Behavior
- Opens the EVTX file at `evtx_path` using Evtx, iterates all records, and parses each
  record's XML into a Python dict using xmltodict.
- Identifies the event ID in each record
- When an event has Event ID "4625" (failed logon), extracts:
    - Account 
    - IPAddress 
  Adds the timestamp to a mapping of IP address -> list of dates
  saves dictionary as a JSON line to `attempts_output_path' (/results/event_logs)

"""

#IMPORTS:
#3rd party
from Evtx.Evtx import Evtx
import xmltodict
#standard
import json
import logging
from datetime import datetime
from collections import defaultdict
#styling
from rich import print as rprint
from rich.console import Console

console = Console()

def file_parser(evtx_path, attempts_output_path):
    try:    
        print('')
        rprint("[bold][rgb(93,0,255)]========= Parsing Event Logs ======================[/rgb(93,0,255)][/bold]")
        logging.info(f"Source file: {evtx_path}")

        #counts artifacts processed, failed logins
        artifact_count = 0
        failed_count = 0
        succesful_count = 0
        # sets a dictionary list to append ip's and timestamps associated with them
        filtered_artifacts = defaultdict(list)
        # saves per event details
        raw_events = []

        #opens the evtx file
        try:
            with Evtx(evtx_path) as log, open(attempts_output_path, "w", encoding="utf-8") as f:
                logging.info("Opened event log.\n\nScanning for Event ID 4625 (failed logins)...")

                # loops through the events in the file
                for record in log.records():
                    artifact_count += 1
                    #converts evtx into dictionary to parse
                    xml_str = record.xml()
                    event_dict = xmltodict.parse(xml_str)

                    #event id dictionary location

                    event_id_node = event_dict["Event"]["System"]["EventID"]

                    #checking if event id is stored in #text to avoid error
                    event_id = (
                        event_id_node["#text"]
                        if isinstance(event_id_node, dict)
                        else event_id_node
                    )

                    # converts system time in dictionary to readable format
                    system_time = event_dict["Event"]["System"]["TimeCreated"]["@SystemTime"]
                    time_created = datetime.fromisoformat(system_time.replace("Z", "+00:00"))

                    #checks for event id 4625 (failed login)
                    if event_id == "4625":
                        failed_count += 1

                        #acceses part of the dictionary that stores event data
                        data_list = event_dict["Event"]["EventData"]["Data"]
                        #acceses account and ip or sets to unkown if missing
                        account = data_list[5]["#text"] if data_list else "Unknown"
                        ip_address = data_list[19]["#text"] if data_list else "Unknown"

                        #stores timestamp of ip addres and or adds a new ip if one apears
                        filtered_artifacts[ip_address].append(time_created)

                        #filtered events log with important info to save into json
                        event_record = {
                            "EventID": event_id,
                            "SystemTime": system_time,
                            "Account": account,
                            "IPAddress": ip_address,
                        }
                        #saves and writes json data to file
                        raw_events.append(event_record)
                        f.write(json.dumps(event_record) + "\n")

                        #logs failed logins with details
                        logging.info(f"Failed login #{failed_count}: Account={account}, IP={ip_address}, Time={system_time}")

                    if event_id == "4624":
                        succesful_count += 1

                        #acceses part of the dictionary that stores event data
                        data_list = event_dict["Event"]["EventData"]["Data"]
                        #acceses account and ip or sets to unkown if missing
                        account = data_list[5]["#text"] if data_list else "Unknown"
                        ip_address = data_list[19]["#text"] if data_list else "Unknown"

                        #stores timestamp of ip addres and or adds a new ip if one apears
                        #filtered_artifacts[ip_address].append(time_created)

                        #filtered events log with important info to save into json
                        event_record = {
                            "EventID": event_id,
                            "SystemTime": system_time,
                            "Account": account,
                            "IPAddress": ip_address,
                        }
                        #saves and writes json data to file
                        #raw_events.append(event_record)
                        #f.write(json.dumps(event_record) + "\n")

                        #logs succesfull logins with details
                        #logging.info(f"Succesfull login #{succesful_count}: Account={account}, IP={ip_address}, Time={system_time}")
                    #counts processed events
                    print(f"\rEvent logs processed: {artifact_count}", end="", flush=True)

            print(flush=True)  # newline after progress counter
            rprint(f"\nFailed Login's Found: {failed_count}\n[bold][rgb(114,255,0)]========== Parsing Complete ========================[rgb(114,255,0)][/bold]\n")
            return filtered_artifacts, raw_events, failed_count
        except FileNotFoundError as file_error:
            logging.error(f'File Missing or Corrupt:{file_error}')
        except Exception as error:
            logging.error(f'Error occured:{error}')        
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        logging.error(e)