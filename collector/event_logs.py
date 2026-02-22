"""
Docstring for collector.event_logs
collects windows events logs for to later parse (Event ID 4625) 
"""

import subprocess

#Runs shell command to find current directory and save it to varieble
Result = subprocess.run(['pwd'], capture_output=True, text=True, shell=True)
ExportLocation = Result.stdout.strip()

ExportLocation= (f'{ExportLocation}/security.evtx')

# run 'wevtutil' shell command with current location to export security logs
subprocess.run(f'wevtutil', 'epl', 'Security', '{ExportLocation}'), check=True


if __name__ == "__main__":
    print('hi')