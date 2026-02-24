"""
Docstring for collector.event_logs
collects windows events logs for to later parse (Event ID 4625) 
"""

import subprocess
from pathlib import Path

def file_path():
    base_dir = Path("Logs/security.evtx")
    path = base_dir.resolve()
    return path

# run 'wevtutil' shell command with current location to export security logs
def wev_run(path):
    subprocess.run(
        ["wevtutil", "epl", "Security", str(path)],
        check=True
    )
def main():
    path = file_path()
    print(path)
    wev_run(path)


if __name__ == "__main__":
    main()