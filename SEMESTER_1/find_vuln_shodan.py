import json

file_path = "product_cves_100.json"

data = []
buffer = ""

with open(file_path, "r") as f:
    for line in f:
        line = line.strip()
        if line.startswith("{") and buffer:  # new object starts
            try:
                data.append(json.loads(buffer))
            except json.JSONDecodeError as e:
                print("Skipping invalid JSON:", e)
            buffer = line
        else:
            buffer += line
    # Don't forget last object
    if buffer:
        try:
            data.append(json.loads(buffer))
        except json.JSONDecodeError as e:
            print("Skipping invalid JSON:", e)

vulnerable_count = 0
non_vulnerable_count = 0

for product in data:
    cves = product.get("cves", {})
    if isinstance(cves, list):
        if cves:
            vulnerable_count += 1
        else:
            non_vulnerable_count += 1
    elif isinstance(cves, dict):
        if cves:
            vulnerable_count += 1
        else:
            non_vulnerable_count += 1
    else:
        non_vulnerable_count += 1

print(f"Total products: {len(data)}")
print(f"Vulnerable products: {vulnerable_count}")
print(f"Non-vulnerable products: {non_vulnerable_count}")