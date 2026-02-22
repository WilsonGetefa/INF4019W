import subprocess
from datetime import datetime
import os
from tabulate import tabulate

# === CONFIGURATION ===
memory_image = "/home/kaliwg/Downloads/windump/WinDump.mem" # <-- Update the path -->
volatility_path = "/home/kaliwg/volatility3/vol.py"         # <-- Update the path -->

plugins = {
    "user_info": "windows.info.Info",                 # <--Show OS & kernel details of the memory sample being analyzed.-->  
    "user_assist": "windows.registry.userassist.UserAssist",            # <--Print userassist registry keys and information.-->
    "print_key": "windows.registry.printkey.PrintKey",                # <--Print registry key and values.-->
    "amcache": "windows.amcache.Amcache",                          # <--Extract information on executed applications from the AmCache (deprecated).-->
    "cmdline": "windows.cmdline.CmdLine",                          # <--Lists process command line arguments.-->
    "cmdscan": "windows.cmdscan.CmdScan",                          # <--Looks for Windows Command History lists-->
    "getcellroutine": "windows.registry.getcellroutine.GetCellRoutine",   # <--Reports registry hives with a hooked GetCellRoutine handler-->
    "getsids": "windows.getsids.GetSIDs",                           # <--Print the SIDs owning each process-->
    "hivelist": "windows.registry.hivelist.HiveList",                # <--Lists the registry hives present in a particular memory image-->
    "malfind": "windows.malware.malfind.Malfind",                   # <--Lists process memory ranges that potentially contain injected code.-->
    "N": "windows.netscan.NetScan",                           # <--Scans for network objects present in a particular windows memory image.-->
    "suspicious_threads": "windows.suspicious_threads.SuspiciousThreads",      # <--Lists suspicious userland process threads (deprecated).-->
    "printkey": "windows.registry.printkey.PrintKey",                # <--Lists the registry keys under a hive or specific key value.-->
    "pslist": "windows.pslist.PsList",                           # <--Lists the processes present in a particular windows memory image.-->
    "psscan": "windows.psscan.PsScan",                           # <--Scans for processes present in a particular windows memory image.-->
    "pstree": "windows.pstree.PsTree",                           # <--Plugin for listing processes in a tree based on their parent process ID.-->
    "sessions": "windows.sessions.Sessions",                         # <--lists Processes with Session information extracted from Environmental Variables-->
    "svcscan": "windows.svcscan.SvcScan",                           # <--Scans for windows services.-->
    #"timeliner": "timeliner.Timeliner",                             # <--Runs all relevant plugins that provide time related information and orders the results by time.-->
    "timers": "windows.timers.Timers",                           # <--Print kernel timers and associated module DPCs-->
}

output_folder = "forensic_outputs"
os.makedirs(output_folder, exist_ok=True)

# === FUNCTION TO FORMAT OUTPUT USING TABULATE ===
def format_with_tabulate(text):
    """
    Converts stdout text into a tabulated table using tabulate.
    Splits lines by multiple spaces.
    """
    lines = text.strip().splitlines()
    if not lines:
        return "No output\n"

    # Split each line by 2+ spaces to infer columns
    table = [line.split() for line in lines]
    if len(table) < 2:
        # Not enough rows to format nicely
        return text

    # Use the first row as header
    headers = table[0]
    data = table[1:]

    return tabulate(data, headers=headers, tablefmt="rounded_grid")

# === RUN PLUGINS ===
for name, plugin in plugins.items():
    print(f"Running plugin: {plugin}")

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(output_folder, f"{name}_{timestamp}.txt")

    cmd = ["python3", volatility_path, "-f", memory_image, plugin]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output_text = result.stdout
        formatted_text = format_with_tabulate(output_text)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(formatted_text)

        print(f"Plugin output saved to {output_file}\n")
    except subprocess.CalledProcessError as e:
        print(f"Plugin {plugin} failed: {e}\n")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Error running plugin:\n{e.stderr}")

print("All plugin outputs saved successfully.")