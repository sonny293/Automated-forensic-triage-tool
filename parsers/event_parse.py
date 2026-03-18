"""
Docstring for event_parser.py
Parses the file collected from Windows event logs.
"""
from Evtx.Evtx import Evtx
from pathlib import Path
import xmltodict
import json
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict

# Logging Setup
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.getLogger("Evtx").setLevel(logging.WARNING)

# dynamic path resolver to open log folder evtx file 
"""
def file_path():
    base_dir = Path(__file__).resolve().parent
    return base_dir.parent / "collector" / "Logs" / "security.evtx"
"""

def file_path():
    base_dir = Path(__file__).resolve().parent
    return base_dir.parent / "collector" / "Logs" / "security-desktop.evtx"

    


path = file_path()

# main file parser, takes evtx file in
def file_parser(path):
    """
    Parses the .evtx log file and extracts all failed login events (Event ID 4625).

    Returns:
        filtered_artifacts (dict): IP -> list of datetime timestamps
        raw_events        (list):  list of dicts with per-event detail
        failed_count      (int):   total number of failed login events found
    """
    logging.info("file_parser: START")
    logging.info(f"Source file: {path}")

    #counts artifacts processed, failed logins
    artifact_count = 0
    failed_count = 0
    # sets a dictionary list to append ip's and timestamps associated with them
    filtered_artifacts = defaultdict(list)
    # saves per event details
    raw_events = []

    #opens the evtx file
    with Evtx(path) as log, open("Security_failed_logins.json", "w", encoding="utf-8") as f:
        logging.info("Opened event log.\nScanning for Event ID 4625 (failed logins)...")
        
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
                logging.debug(f"Failed login #{failed_count}: Account={account}, IP={ip_address}, Time={system_time}")
            #counts processed events
            print(f"\rEvent logs processed: {artifact_count}", end="", flush=True)

    print()  # newline after progress counter
    logging.info(f"file_parser: END — {artifact_count} events scanned, {failed_count} failed logins found\n")
    return filtered_artifacts, raw_events, failed_count


def scoring(filtered_artifacts, risk_threshold, time_window_minutes=5):
    """
    Scores each IP address by the maximum number of failed logins within any
    time window of `time_window_minutes`.

    Priority levels
        High   — attempts >= risk_threshold
        Medium — attempts >= risk_threshold // 2 and < threshold
        Low    — anything lower

    Returns:
        risky_ips (dict): IP -> 'max_attempts': int, 'priority': str
    """
    logging.info("scoring: START")
    logging.info(
        f"Parameters — risk_threshold={risk_threshold}, time_window_minutes={time_window_minutes}"
    )

    #counts ips, and sets priorities to 0
    total_ips = len(filtered_artifacts)
    high_count = medium_count = low_count = 0
    #sets dictionary to store ip's with risk
    risky_ips = {}

    #loops over ip/timestamps
    for idx, (ip_address, timestamps) in enumerate(filtered_artifacts.items(), start=1):
        #sorts order of timestamps to make comparing work
        timestamps.sort()
        max_attempts_in_window = 0
        window_start = 0

        #sliding window algorithm to find most failed attemps within time window
        #iterates through incrementing to the timestamp total range
        for window_end in range(len(timestamps)):
            #checks if the timestamp range is bigger than range
            while (
                timestamps[window_end] - timestamps[window_start]
            ) > timedelta(minutes=time_window_minutes):
                #iterates though timestamps if time window is greater than set window
                window_start += 1
            #counts attemots within time window +1 to account for inclusivity (part of the same data)    
            count = window_end - window_start + 1
            #if the count of attemepts is larger than previouse attempt max it is set to the new max
            if count > max_attempts_in_window:
                max_attempts_in_window = count

        # Assign priority
        # checks if max attemots found are greater than set thresholf
        if max_attempts_in_window >= risk_threshold:
            #sets priority, and count
            priority = "High"
            high_count += 1
            logging.warning(
                f"[{idx}/{total_ips}] IP {ip_address} — HIGH priority: "
                f"{max_attempts_in_window} attempts in {time_window_minutes} min window "
                f"(threshold={risk_threshold})"
            )
        elif max_attempts_in_window >= risk_threshold // 2:
            priority = "Medium"
            medium_count += 1
            logging.info(
                f"[{idx}/{total_ips}] IP {ip_address} — MEDIUM priority: "
                f"{max_attempts_in_window} attempts in {time_window_minutes} min window"
            )
        else:
            priority = "Low"
            low_count += 1
            logging.debug(
                f"[{idx}/{total_ips}] IP {ip_address} — LOW priority: "
                f"max {max_attempts_in_window} attempts — below threshold"
            )

        #sets attempts and priority set in scoring to add to json
        risky_ips[ip_address] = {
            "max_attempts": max_attempts_in_window,
            "priority": priority,
        }

    logging.info(
        f"scoring: END — {total_ips} IPs evaluated | "
        f"High={high_count}, Medium={medium_count}, Low={low_count}\n"
    )
    return risky_ips


def write_json_report(raw_events, risky_ips, risk_threshold, time_window_minutes, execution_duration_seconds):
    """
    Writes a single consolidated JSON report containing:
      - Run metadata (thresholds, execution duration)
      - artefact details (account, IP, timestamp)
      - IP attempts scoring summary (max attempts, priority)
    """
    #sets output name, logs path
    output_path = "Security_report.json"
    logging.info(f"Writing JSON report to {output_path}")

    # Attach priority to each raw event (artifact + score)
    #combines two seperate sets of data, raw event data (parsing) + risky ip (scoring)
    enriched_events = []
    #iterates through events in raw events
    for event in raw_events:
        #sets ip from raw events (common factor betwean data to link)
        ip = event["IPAddress"]
        #gets the scoring info by using the ip from raw events as a key
        #defualts to {max_a...} if somehow it doesnt match
        score_info = risky_ips.get(ip, {"max_attempts": 0, "priority": "Low"})
        #adds them all together in a list, where **event expands the raw event data
        #plus score_info (scoring of ip)
        enriched_events.append({
            **event,
            "AssignedPriority": score_info["priority"],
            "MaxAttemptsInWindow": score_info["max_attempts"],
        })


    #sets the report layout for the json file
    report = {
        "RunMetadata": {
            "RiskThreshold": risk_threshold,
            "TimeWindowMinutes": time_window_minutes,
            "ExecutionDurationSeconds": round(execution_duration_seconds, 3),
        },
        #iterates over ip's and data stored in risky ip's
        "ScoredIPs": {
            ip: data for ip, data in risky_ips.items()
        },
        "Artefacts": enriched_events,
    }
    #writes data to a file
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    logging.info(f"JSON report written: {len(enriched_events)} artefacts, {len(risky_ips)} IPs scored.\n")


def timer(start, end):
    """Returns (seconds, minutes, hours) breakdown of elapsed time."""
    elapsed = end - start
    #floo divvison of hours so nothing is left over messy
    hours = int(elapsed // 3600)
    #remaining counts what would be taken away in above floor division
    remaining = elapsed % 3600
    #minutes uses remaining to floor devide minutes
    minutes = int(remaining // 60)
    #seconds also uses remaining to calc secs but used modulo to leave more
    seconds = remaining % 60
    #seconds are rounded to 3 decimal places and returned
    return round(seconds, 3), minutes, hours


def main():
    pass


if __name__ == "__main__":

    # Configurable thresholds
    risk_threshold = int(input("Set risk threshold for failed login attempts: "))
    time_window_minutes = int(input("Set time window in minutes for rolling analysis (default 5): ") or 5)

    overall_start = time.time()

    # Parsing phase
    parse_start = time.time()
    filtered_artifacts, raw_events, failed_count = file_parser(path)
    parse_end = time.time()
    parse_secs, parse_mins, parse_hrs = timer(parse_start, parse_end)
    logging.info(f"Parsing duration: {parse_hrs}h {parse_mins}m {parse_secs}s")

    print(f"\nFailed logins found: {failed_count}")

    # Scoring phase
    score_start = time.time()
    risky_ips = scoring(filtered_artifacts, risk_threshold, time_window_minutes)
    score_end = time.time()
    score_secs, score_mins, score_hrs = timer(score_start, score_end)
    logging.info(f"Scoring duration: {score_hrs}h {score_mins}m {score_secs}s")

    # Overall timing
    overall_end = time.time()
    total_secs, total_mins, total_hrs = timer(overall_start, overall_end)
    total_elapsed = overall_end - overall_start
    logging.info(f"Total execution duration: {total_hrs}h {total_mins}m {total_secs}s")

    # JSON report
    write_json_report(raw_events, risky_ips, risk_threshold, time_window_minutes, total_elapsed)

    print(f"\nProcessing Time — Seconds: {total_secs}  Mins: {total_mins}  Hours: {total_hrs}")