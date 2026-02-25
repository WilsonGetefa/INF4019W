import subprocess
from tabulate import tabulate
from datetime import datetime
import os

# Output folder
output_folder = "Volatility_Reports"
os.makedirs(output_folder, exist_ok=True)

# Plugins to run
plugins = {
    "pslist": "windows.pslist",
    "psscan": "windows.psscan",
    "psxview": "windows.psxview"
}

# Paths
volatility_path = "/home/kaliwg/volatility3/vol.py"
memory_image = "/home/kaliwg/Downloads/windump/WinDump.mem"

for name, plugin in plugins.items():
    print(f"\nRunning plugin: {plugin}")

    # Build command
    cmd = ["python3", volatility_path, "-f", memory_image, plugin]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Parse output into rows using simple split()
    rows = []
    for line in result.stdout.splitlines():
        if line.strip() and "Progress:" not in line:  # skip progress
            rows.append(line.split())

    # Tabulate and print
    table = tabulate(rows, tablefmt="grid")
    print(table)

    # Save to TXT
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(output_folder, f"{name}_{timestamp}.txt")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(table)

    print(f"Plugin output saved to {output_file}")
