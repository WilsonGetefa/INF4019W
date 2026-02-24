import subprocess
from datetime import datetime
import os

# ================= CONFIGURATION =================

memory_image   = "/home/kaliwg/Downloads/windump/WinDump.mem"
volatility_path = "/home/kaliwg/volatility3/vol.py"

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

# Output directory
output_folder = "forensic_outputs_10"
os.makedirs(output_folder, exist_ok=True)

# Timestamp for this run
run_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

print("\n========== VOLATILITY AUTOMATION START ==========\n")

# ================= EXECUTION =================

for name, plugin in plugins.items():

    print(f"Running → {name:18} ({plugin})")

    output_file = os.path.join(output_folder, f"{name}_{run_timestamp}.txt")

    # ⭐ Correct renderer usage
    cmd = [
        "python3",
        volatility_path,
        "-f", memory_image,
        "-r", "pretty",      # <-- KEY FIX
        plugin
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900,   # 15 min per plugin
            check=False
        )

        # Always capture something
        output = result.stdout if result.stdout else result.stderr

        # Save output
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output)

        print(f"  ✔ Saved → {output_file}\n")

    except subprocess.TimeoutExpired:
        print(f"  ⏱ TIMEOUT → {name}")
        with open(output_file, "w") as f:
            f.write("Plugin timed out after 15 minutes.\n")

    except Exception as exc:
        print(f"  ❌ Failed → {name}: {exc}")
        with open(output_file, "w") as f:
            f.write(str(exc))

print("\n========== ALL PLUGINS FINISHED ==========\n")