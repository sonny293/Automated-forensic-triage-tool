"""
Path Finder
Dynamically finds the relative path to the extracetd evtx file and sets the location to 
save results to. since when the progra is run on another machine it wont be in the same directory.
"""

#imports
from pathlib import Path
import os


def path_find():
    #finds current file location relative to system its on
    base_dir = Path(__file__).resolve().parent
    #connects the dynamic location of the machine to the static log file location.
    evtx_path = base_dir.parent / "collector" / "Logs" / "security.evtx"


    #finds current directory
    tool_dir = os.path.dirname(os.path.abspath(__file__))
    tool_dir = os.path.dirname(tool_dir)  # go up one level

    #joins current directory to the results folder
    report_output_path = os.path.join(tool_dir, "results/event_logs", "report.json")
    attempts_output_path = os.path.join(tool_dir, "results/event_logs", "failed_attempts.json")

    #returns variouse paths for other scripts to use
    return evtx_path, report_output_path, attempts_output_path, browser_path, browser_output_path

def brow_path_find():
    base_dir = Path(__file__).resolve().parent
    browser_path = base_dir.parent / "collector" / "Browser_Hist" / "History.json"
    browser_output_path = os.path.join(tool_dir, "results/browser_history", "filtered_history.json")

    return browser_path, browser_output_path
