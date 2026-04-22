"""
Writes a single consolidated JSON report containing:
- Run metadata (thresholds, execution duration)
- artefact details (account, IP, timestamp)
- IP attempts scoring summary (max attempts, priority)
"""

#imports
import json
import logging
#styling
from rich import print as rprint

def write_json_report(raw_events, risky_ips, risk_threshold, time_window_minutes, execution_duration_seconds, report_output_path):
    try:
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
        try:
            with open(report_output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)
        except Exception as error:
            logging.error(f'Error occured:{error}')
        print("\n")
        rprint("[bold][rgb(114,255,0)]============ Report Saved ==========================[/rgb(114,255,0)][/bold]")
        logging.info(f"JSON report written: {len(enriched_events)} artefacts, {len(risky_ips)} IPs scored.")
        logging.info(f'Saved file to:{report_output_path}')
    except KeyboardInterrupt:
                exit()
    except Exception as e:
        logging.error(e)   