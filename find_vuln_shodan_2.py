#!/usr/bin/env python3
import json

# Path to your JSON file
file_path = "ZA_ICS_30_Filter.json"

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

# Process each product
for product in data:
    print(product.keys())  # Debug: print keys of the product
    cves = product.get("cves", {})
    is_vulnerable = bool(cves)
    
    ip = product.get("ip_str", product.get("ip", "Unknown IP"))  # Try ip_str first, fallback to ip
    hostnames = product.get("hostnames", [])                     # Hostnames as list
    
    if is_vulnerable:
        vulnerable_count += 1
        print(f"\nIP: {ip}")
        print(f"Hostnames: {', '.join(hostnames) if hostnames else 'None'}")
        print(f"Product: {product.get('product')} {product.get('version')}")
        
        # Handle list of CVEs
        if isinstance(cves, list):
            for cve in cves:
                print(f"  - {cve}")
        # Handle dict of CVEs with details
        elif isinstance(cves, dict):
            for cve_id, details in cves.items():
                summary = details.get("summary", "No summary")
                cvss = details.get("cvss", "N/A")
                epss = details.get("epss", "N/A")
                references = details.get("references", [])
                print(f"  - {cve_id} | CVSS: {cvss} | EPSS: {epss}")
                print(f"      Summary: {summary}")
                for ref in references:
                    print(f"      Reference: {ref}")
    else:
        non_vulnerable_count += 1

# Summary
print("\n" + "="*50)
print(f"Total products: {total_products}")
print(f"Vulnerable products: {vulnerable_count}")
print(f"Non-vulnerable products: {non_vulnerable_count}")
print("="*50)