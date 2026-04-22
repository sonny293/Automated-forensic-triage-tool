"""
collects browser (chrome) history to later parse 


"""
import sqlite3
import os
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

def get_history():
    #ubuntu linux
    #db_path = os.path.expanduser('~/.config/google-chrome/Default/History')
    #windows
    db_path = os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History')
    try:
        with sqlite3.connect(db_path) as con:
            c = con.cursor()
            c.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
            results = c.fetchall()
            logging.info("Chrome History collected Succesfully")
            return results
            
    except Exception as e:
        logging.error(f"[Error] get_history failed: {e}")
        logging.error("[HINT] - Make sure chrome is not open when running")
        return []

def path():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    tool_dir = os.path.dirname(script_dir)
    output_path = os.path.join(tool_dir, "collector", "Browser_Hist", "History.json")
    # ensure dir exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    return output_path

def write_history(results, output_path):
    if not results:
        logging.info("No history results to write.")
        history = {"History": []}
    else:
        history = {
            "History": [
                {
                    "URL": row[0],
                    "Title": row[1],
                    "Visit_Count": row[2],
                    "Last_Visit_Time": row[3],
                }
                for row in results
            ]
        }
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, default=str)
            logging.info("Chrome Browser History JSON report written")
            logging.info(output_path)
    except Exception as e:
        logging.error(f"Error writing JSON: {e}")

def main():
    results = get_history()
    output_path = path()
    write_history(results, output_path)

if __name__ == "__main__":
    main()
