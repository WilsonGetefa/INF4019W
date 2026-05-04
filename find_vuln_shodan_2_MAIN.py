#!/usr/bin/env python3
import json

# Path to your JSON file
file_path = "ZA_ICS_30_Filter.json"
output_file = "SHODAN/ZA_ICS_30_Filter_report.txt"

# Function to safely parse JSON objects (one per line or multiple objects)
def load_json_objects(file_path):
    objects = []
    with open(file_path, "r") as f:
        content = f.read().strip()
    # Split by '}{' and add braces back
    parts = content.replace("}\n{", "}|||{").split("|||")
    for part in parts:
        try:
            obj = json.loads(part)
            objects.append(obj)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
    return objects

# Load data
data = load_json_objects(file_path)

# Counters
total_products = len(data)
vulnerable_count = 0
non_vulnerable_count = 0

# Open output file
with open(output_file, "w") as out:

    # Process each product
    for product in data:
        cves = product.get("cves", {})
        is_vulnerable = bool(cves)
        
        ip = product.get("ip_str", product.get("ip", "Unknown IP"))
        type = product.get("type", [])
        
        if is_vulnerable:
            vulnerable_count += 1
            out.write(f"\nIP: {ip}\n")
            out.write(f"type: {', '.join(type) if type else 'None'}\n")
            out.write(f"Product: {product.get('product')} {product.get('version')}\n")
            
            # Handle list of CVEs
            if isinstance(cves, list):
                for cve in cves:
                    out.write(f"  - {cve}\n")
            # Handle dict of CVEs with details
            elif isinstance(cves, dict):
                for cve_id, details in cves.items():
                    summary = details.get("summary", "No summary")
                    cvss = details.get("cvss", "N/A")
                    epss = details.get("epss", "N/A")
                    references = details.get("references", [])
                    out.write(f"  - {cve_id} | CVSS: {cvss} | EPSS: {epss}\n")
                    out.write(f"      Summary: {summary}\n")
                    for ref in references:
                        out.write(f"      Reference: {ref}\n")
        else:
            non_vulnerable_count += 1

    # Summary
    out.write("\n" + "="*50 + "\n")
    out.write(f"Total products: {total_products}\n")
    out.write(f"Vulnerable products: {vulnerable_count}\n")
    out.write(f"Non-vulnerable products: {non_vulnerable_count}\n")
    out.write("="*50 + "\n")

print(f"Report written to {output_file}")