import subprocess
from tabulate import tabulate
from datetime import datetime
import os

# Output folder
output_folder = "Volatility_Reports_New_7"
os.makedirs(output_folder, exist_ok=True)

# Plugins to run
plugins = {
    "user_info": "windows.info.Info",                 # <--Show OS & kernel details of the memory sample being analyzed.-->  
    "user_assist": "windows.registry.userassist.UserAssist",            # <--Print userassist registry keys and information.-->
    "amcache": "windows.amcache.Amcache",                          # <--Extract information on executed applications from the AmCache (deprecated).-->
    "cmdline": "windows.cmdline.CmdLine",                          # <--Lists process command line arguments.-->
    "cmdscan": "windows.cmdscan.CmdScan",                          # <--Looks for Windows Command History lists-->
    "getcellroutine": "windows.registry.getcellroutine.GetCellRoutine",   # <--Reports registry hives with a hooked GetCellRoutine handler-->
    "getsids": "windows.getsids.GetSIDs",                           # <--Print the SIDs owning each process-->
    "hivelist": "windows.registry.hivelist.HiveList",                # <--Lists the registry hives present in a particular memory image-->
    "malfind": "windows.malware.malfind.Malfind",                   # <--Lists process memory ranges that potentially contain injected code.-->
    "Netscan": "windows.netscan.NetScan",                           # <--Scans for network objects present in a particular windows memory image.-->
    "suspicious_threads": "windows.suspicious_threads.SuspiciousThreads",      # <--Lists suspicious userland process threads (deprecated).-->
    "printkey": "windows.registry.printkey.PrintKey",                # <--Lists the registry keys under a hive or specific key value.-->
    "pslist": "windows.pslist.PsList",                           # <--Lists the processes present in a particular windows memory image.-->
    "psscan": "windows.psscan.PsScan",                           # <--Scans for processes present in a particular windows memory image.-->
    "pstree": "windows.pstree.PsTree",                           # <--Plugin for listing processes in a tree based on their parent process ID.-->
    "sessions": "windows.sessions.Sessions",                         # <--lists Processes with Session information extracted from Environmental Variables-->
    "svcscan": "windows.svcscan.SvcScan",                           # <--Scans for windows services.-->
    #"timeliner": "timeliner.Timeliner",                             # <--Runs all relevant plugins that provide time related information and orders the results by time.-->
    "timers": "windows.timers.Timers",                           # <--Print kernel timers and associated module DPCs-->
    "processView": "windows.malware.psxview",                            # <--Prints the process list by using the Windows EPROCESS ActiveProcessLinks and ActiveProcessHead lists.-->
    "hashdump": "windows.registry.hashdump.HashDump",                # <--Extracts password hashes from the SAM registry hive.-->
}

# Paths
volatility_path = "/home/kaliwg/volatility3/vol.py"
memory_image = "/home/kaliwg/Downloads/AdamFTriage.mem"

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