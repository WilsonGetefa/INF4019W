import subprocess
from datetime import datetime
import os
from tabulate import tabulate

# === CONFIGURATION ===
memory_image = "/home/kaliwg/Downloads/windump/WinDump.mem"
volatility_path = "/home/kaliwg/volatility3/vol.py"  # <-- update if needed

plugins = {
    "os_info": "windows.info.Info",
    "user_assist": "windows.registry.userassist.UserAssist",
    "print_key": "windows.registry.printkey.PrintKey",
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