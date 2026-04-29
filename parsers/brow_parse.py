import json
from datetime import datetime, timedelta
import logging
#styling
from rich import print as rprint

WEBKIT_EPOCH_START = datetime(1601, 1, 1)

def webkit_time_to_iso(webkit_ts):
    try:
        us = int(webkit_ts)
    except Exception:
        return None
    # Chrome stores microseconds since 1601; some exports use 100-ns ticks — adjust if values are huge.
    # If value looks like Windows FILETIME (100-ns ticks), convert to microseconds:
    if us > 10**17:  # rough threshold for 100-ns ticks
        us = us // 10
    # If value looks like milliseconds, detect small numbers:
    if us < 10**12:
        # likely milliseconds
        us = us * 1000
    dt = WEBKIT_EPOCH_START + timedelta(microseconds=us)
    return dt.isoformat() + 'Z'

def load_history(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data.get('History', [])

def matches(entry, keyword):
    k = keyword.lower()
    return (k in (entry.get('URL','') or '').lower()) or (k in (entry.get('Title','') or '').lower())

def normalize_entry(entry):
    e = dict(entry)  # shallow copy
    if 'Last_Visit_Time' in e:
        e['Last_Visit_ISO'] = webkit_time_to_iso(e['Last_Visit_Time'])
    return e

def search_history(json_path, keyword):
    history = load_history(json_path)
    results = []
    for entry in history:
        if matches(entry, keyword):
            results.append(normalize_entry(entry))
    print(f'\n{len(results)} Matches')
    return results

def brow_report(results, browser_output_path):
    try:
        with open(browser_output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
    except Exception as error:
            logging.error(f'Error occured:{error}')
    print("\n")
    rprint("[bold][rgb(114,255,0)]============ Filtered Browser Saved ===============[/rgb(114,255,0)][/bold]")
    logging.info(f'Saved file to:{browser_output_path}')


if __name__ == '__main__':

    exit()
