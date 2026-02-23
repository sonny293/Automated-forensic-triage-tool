"""
Docstring for collector.event_logs
collects windows events logs for to later parse (Event ID 4625) 
"""

import subprocess
from pathlib import Path

#Runs shell command to find current directory and save it to varieble
"""
Result = subprocess.run(['pwd'], capture_output=True, text=True, shell=True)
ExportLocation = Result.stdout.strip()
"""
# collects current directory and joins it to file name for export location
"""
change to appropriate location
"""

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