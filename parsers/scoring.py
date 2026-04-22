"""
Scores each IP address by the maximum number of failed logins within any
time window of `time_window_minutes`.

inputs:
filtered artifacts - (dictionary list) of ip's sorted with the times that thos ips failed login
risk threshold - (input) amount of login atmpts within time window to be deemed a risk
time window - (input) default 5 mins time window or set by user 

Priority levels
High   — attempts >= risk_threshold
Medium — attempts >= risk_threshold // 2 and < threshold
Low    — anything lower

Returns:
risky_ips (dict): IP -> 'max_attempts': int, 'priority': str

"""

#imports
import logging
from datetime import timedelta
#styling
from rich import print as rprint
from rich.console import Console

def scoring(filtered_artifacts, risk_threshold, time_window_minutes=5):
    try:
        rprint("[bold][rgb(197,0,255)]========== Scoring Started =========================[/rgb(197,0,255)][/bold ]")
        total_ips = len(filtered_artifacts)
        high_count = medium_count = low_count = 0
        risky_ips = {}

        #enumerates over ip's timestamps
        for idx, (ip_address, timestamps) in enumerate(filtered_artifacts.items(), start=1):
            #sorts for the sliding windows algo
            timestamps.sort()
            max_attempts_in_window = 0
            window_start = 0

            #Scores each IP address by the maximum number of failed logins within any
            #time window of `time_window_minutes`.
            for window_end in range(len(timestamps)):
                #checks if the timestamp range is bigger than range
                while (timestamps[window_end] - timestamps[window_start]) > timedelta(minutes=time_window_minutes):
                    #iterates though timestamps if time window is greater than set window
                    window_start += 1
                #counts attemots within time window +1 to account for inclusivity (part of the same data)
                count = window_end - window_start + 1
                #if the count of attempts is larger than previouse attempt max it is set to the new max
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
                    logging.info(
                        f"[{idx}/{total_ips}] IP {ip_address} — LOW priority: "
                        f"max {max_attempts_in_window} attempts — below threshold"
                    )

                #sets attempts and priority set in scoring to add to json
                risky_ips[ip_address] = {
                    "max_attempts": max_attempts_in_window,
                    "priority": priority,
                }

            logging.info(
                f"High={high_count}, Medium={medium_count}, Low={low_count}\n"
                f"\nIP's Evaluated: {total_ips}"
            )
            rprint("[bold][rgb(114,255,0)]========== Scoring Complete ========================[/rgb(114,255,0)][/bold]")
            return risky_ips
    except KeyboardInterrupt:
                exit()
    except Exception as e:
        logging.error(e)