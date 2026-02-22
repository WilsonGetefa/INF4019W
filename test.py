import subprocess
from datetime import datetime
import os
import re
from tabulate import tabulate

# ================= CONFIG =================
memory_image = "/home/kaliwg/Downloads/windump/WinDump.mem"
volatility_path = "/home/kaliwg/volatility3/vol.py"

plugins = {
    "user_info": "windows.info.Info",
    "pslist": "windows.pslist.PsList",
    "pstree": "windows.pstree.PsTree",
    "psscan": "windows.psscan.PsScan",
    "cmdline": "windows.cmdline.CmdLine",
    "cmdscan": "windows.cmdscan.CmdScan",
    "netscan": "windows.netscan.NetScan",
    "malfind": "windows.malware.malfind.Malfind",
    "svcscan": "windows.svcscan.SvcScan",
    "hivelist": "windows.registry.hivelist.HiveList",
    "printkey": "windows.registry.printkey.PrintKey",
    "userassist": "windows.registry.userassist.UserAssist",
    "amcache": "windows.amcache.Amcache",
    "getsids": "windows.getsids.GetSIDs",
    "sessions": "windows.sessions.Sessions",
    "timers": "windows.timers.Timers",
    "suspicious_threads": "windows.suspicious_threads.SuspiciousThreads",
}

output_folder = "forensic_outputs_1"
os.makedirs(output_folder, exist_ok=True)


# ================= CLEAN VOL OUTPUT =================
def clean_volatility_output(text: str) -> str:
    """
    Remove banner + progress lines only.
    Keeps actual table intact.
    """
    cleaned = []

    for line in text.splitlines():
        if line.startswith("Volatility 3 Framework"):
            continue
        if line.strip().startswith("Progress:"):
            continue
        if "PDB scanning finished" in line:
            continue
        cleaned.append(line)

    return "\n".join(cleaned).strip()


# ================= TABULATE PARSER =================
def tabulate_volatility_output(text: str) -> str:
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        return text

    # Detect header
    header_idx = -1
    for i, line in enumerate(lines):
        if re.match(r"^-{3,}", line):  # skip dashed lines
            continue
        cols = re.split(r'\s{2,}', line.strip())
        if len(cols) >= 2:
            header_idx = i
            break

    if header_idx == -1:
        return text

    table_lines = []
    for l in lines[header_idx:]:
        if re.match(r"^-{3,}", l):
            continue
        table_lines.append(re.split(r'\s{2,}', l.strip()))

    headers = table_lines[0]
    data = table_lines[1:]

    # Normalize column count
    max_cols = max(len(headers), max((len(r) for r in data), default=0))
    headers += [""] * (max_cols - len(headers))
    for row in data:
        row += [""] * (max_cols - len(row))

    return tabulate(
        data,
        headers=headers,
        tablefmt="rounded_grid",
        disable_numparse=True,
        stralign="left",
        numalign="left"
    )

# ================= MAIN LOOP =================
for name, plugin in plugins.items():
    print(f"Running → {name:18} ({plugin})")

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(output_folder, f"{name}_{timestamp}.txt")

    cmd = ["python3", volatility_path, "-f", memory_image, plugin]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900,
            check=False
        )

        raw_output = result.stdout if result.stdout else result.stderr

        # ⭐ Step 1: clean banner
        cleaned = clean_volatility_output(raw_output)

        # ⭐ Step 2: tabulate
        formatted = tabulate_volatility_output(cleaned)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(formatted)

        print(f"  Saved → {output_file}\n")

    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT → {name}")
        with open(output_file, "w") as f:
            f.write("Plugin timed out.\n")

    except Exception as e:
        print(f"  ERROR → {name}: {e}")
        with open(output_file, "w") as f:
            f.write(str(e))

print("\n✅ All plugins finished")


