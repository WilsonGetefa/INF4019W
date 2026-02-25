import subprocess
from tabulate import tabulate

cmd = ["python3","/home/kaliwg/volatility3/vol.py","-f","/home/kaliwg/Downloads/windump/WinDump.mem","windows.pslist"]
result = subprocess.run(cmd, capture_output=True, text=True)

rows = []
for line in result.stdout.splitlines():
    if line.strip():
        rows.append(line.split())

print(tabulate(rows, tablefmt="grid"))
