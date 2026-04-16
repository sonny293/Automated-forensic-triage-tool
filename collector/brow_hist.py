"""
Docstring for collector.event_logs
collects browser history to later parse 
"""

import subprocess
from pathlib import Path
import logging
import sqlite3
import os
import json

logging.basicConfig(
    level=logging.DEBUG,  # minimum level to show
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def get_history():

    con = sqlite3.connect('/home/eliptic/.config/google-chrome/Default/History')
    c = con.cursor()

    # query
    c.execute("select url, title, visit_count, last_visit_time from urls") 
    results = c.fetchall()

    for r in results:
        print(r)

    c.close()
    return results
    

def path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    tool_dir = os.path.dirname(script_dir)  
    try:
        output_path = os.path.join(tool_dir, "collector", "Browser_Hist", "History.json")
    except Exception as error:
        print(f'Error occured:{error}')
    return output_path


def write_history(results, output_path):    
    #sets the layout for the json file
    history = {
        "History": [
            {
                "URL": row[0],
                "Title": row[1],
                "Visit_Count": row[2],
                "Last_Visit_Tine": row[3],
            }
            for row in results
        ]
    }

    #writes data to a file
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, default=str)
            logging.info(f"JSON report written")
    except Exception as error:
        print(f'Error occured:{error}')







def main():
    results = get_history()
    output_path = path()
    write_history(results, output_path)


if __name__ == "__main__":
    main()