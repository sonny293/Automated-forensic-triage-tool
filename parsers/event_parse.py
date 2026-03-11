"""
Docstring for event_parser.py
parses the file collected from windows event logs
"""
from Evtx.Evtx import Evtx
from pathlib import Path
import xmltodict
import json
from pathlib import Path
import time
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict

#loggin

logging.basicConfig(
    level=logging.DEBUG,  # minimum level to show
    format="%(asctime)s - %(message)s"
)
logging.getLogger("Evtx").setLevel(logging.WARNING)

def file_path():
    base_dir = Path(__file__).resolve().parent
    path = base_dir.parent / "collector" / "Logs" / "security.evtx"
    return path

path = file_path()
#path = r"/Users/sonnybowers/Documents/University/Group Project/AFTT/main/Automated-forensic-triage-tool/collector/Logs/time_takenurity.evtx"

def file_parser(path):
    Artifact_count=0  
    Failed_count=0

    filtered_artifacts = defaultdict(list)
    logging.debug("Loading Windows security.evtx Event Log")

    with Evtx(path) as log, open("Security_failed_logins.json", "w", encoding="utf-8") as f:
        logging.debug("Converting Event Log Into JSON Dictionay\n")
        logging.debug("Searching for Failed Logins\n")   
        for record in log.records():
            Artifact_count+=1

            #logging.info(f"Artifact:{Artifact_count} Processing")
            xml_str = record.xml()

            # Convert XML string to Python dict
            event_dict = xmltodict.parse(xml_str)

            EventID = event_dict["Event"]["System"]["EventID"]["#text"]
            SystemTime = event_dict["Event"]["System"]["TimeCreated"]["@SystemTime"]
            time_created = datetime.fromisoformat(SystemTime.replace('Z', '+00:00'))

            event_id = event_dict["Event"]["System"]["EventID"]["#text"]
            
            #failed login
            if event_id == "4625":
                Failed_count += 1
                #filtered_artifacts[EventID].append(time_created)

                #filter the dictionary for needed fields
                filtered = {
                "EventID": event_dict["Event"]["System"]["EventID"]["#text"],
                "SystemTime": event_dict["Event"]["System"]["TimeCreated"]["@SystemTime"],
                }

                #logging failed logins to json file
                f.write(json.dumps(filtered) + "\n")

                #flushing line to log failed login to terminal without overalap of count
                print(f"\r", end="", flush=True)
                logging.debug(f"\rFailed Loggin Attempt:{filtered}")

                data_list = event_dict["Event"]["EventData"]["Data"]

                if data_list != None:
                    account = data_list[5]["#text"]
                    ip_address = data_list[19]["#text"]
                    filtered_artifacts[ip_address].append(time_created)


                    print("Account: " + account)
                    print("IP Address: " + ip_address + "\n")
            

            print(f"\rEvent Log/s Processed: {Artifact_count}", end="", flush=True)

        print(f"\n\nFailed Loggin/s Found: {Failed_count}")

    #print(filtered_artifacts)
    
    #return filtered_artifacts, ip_address, account, Failed_count
    return filtered_artifacts, account, Failed_count

"""
def scoring(filtered_artifacts, ip_address):
    logging.debug(f"Calculating Risk Priority")
    # Dictionary to hold IP addresses and their corresponding timestamps
    failed_attempts = defaultdict(list)

    logging.debug(f"Calculating Attempts per IP")
    # Convert timestamp to datetime object and extract time components
    for event_id, timestamps in filtered_artifacts.items():
        for timestamp in timestamps:
        # Append timestamp to corresponding IP address
            failed_attempts[ip_address].append(timestamp)

    logging.debug(f"Calculating Frequency of attempts per IP")
    # Check for failed attempts within time range
    brute_force = [ts for ts in failed_attempts[ip_address] if ts >= ts - timedelta(minutes=5)]
    suspicious = [ts for ts in failed_attempts[ip_address] if ts >= ts - timedelta(minutes=10)]

    logging.debug(f"Scoring Risk Priority\n")
    #scoring logic
    if len(brute_force) >= 5:
        logging.debug(f"Potential brute force attack detected\nIP {ip_address}: {len(brute_force)} failed attempts within 5 minutes.\n")
    elif len(suspicious) >= 2 < 5:
        logging.debug(f"Suscpicious activity\n{len(suspicious)} - failed attempts - IP: {ip_address} - within 10 minutes.\n")
    else:
        logging.debug(f"likley user error\n {account}: {len(suspicious)} failed login attempts.\n")
"""

def scoring(filtered_artifacts, risk_threshold=1):
    logging.debug("Calculating Risk Priority")

    # Dictionary to hold counts of login attempts per IP
    ip_attempt_counts = {}

    for ip_address, timestamps in filtered_artifacts.items():
        # Initialize the login attempt counter for the IP
        ip_attempt_counts[ip_address] = 0
        
        # Count the number of attempts within the last 5 minutes
        recent_attempts = [
            ts for ts in timestamps if ts >= (max(timestamps) - timedelta(minutes=5))
        ]

        # Update the count for the current IP address
        ip_attempt_counts[ip_address] = len(recent_attempts)

        # Log if the attempts are considered risky
        if ip_attempt_counts[ip_address] >= risk_threshold:
            logging.warning(f"Risky login attempts: {ip_attempt_counts[ip_address]} from IP {ip_address}")

    return ip_attempt_counts

def timer(start, end):

    time_taken= end - start
    hour = int(time_taken // 3600)
    remaining = time_taken % 3600
    min = int(remaining // 60)
    time_taken = remaining % 60

    return time_taken, min, hour



def main():
    print("....")


if __name__ == "__main__":

    start = time.time()
    #filtered_artifacts, ip_address, account, Failed_count = file_parser(path)
    filtered_artifacts, account, Failed_count = file_parser(path)
    #scoring(filtered_artifacts, ip_address)
    scoring(filtered_artifacts)
    end = time.time()


    time_taken, min, hour = timer(start, end)

    print(f"\nProcessing Time Taken:\nSeconds:{round(time_taken, 3)} Mins:{min} Hours:{hour}") 



