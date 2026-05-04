#!/usr/bin/env python3
import json

# Path to your JSON file
file_path = "product_cpes_cves_with_ip.json"
vuln_file = "vulnerable_products_report.txt"
non_vuln_file = "non_vulnerable_products_report.txt"

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

# Open output files
with open(vuln_file, "w") as out_vuln, open(non_vuln_file, "w") as out_nonvuln:

    # Process each product
    for product in data:
        cves = product.get("cves", {})
        is_vulnerable = bool(cves)
        
        ip = product.get("ip_str", product.get("ip", "Unknown IP"))
        hostnames = product.get("hostnames", [])
        product_type = product.get("type", "UNKNOWN")
        product_name = product.get("product", "Unknown")
        version = product.get("version", "")

        if is_vulnerable:
            vulnerable_count += 1
            out_vuln.write(f"\nIP: {ip}\n")
            out_vuln.write(f"Hostnames: {', '.join(hostnames) if hostnames else 'None'}\n")
            out_vuln.write(f"Product: {product_name} {version}\n")
            
            if isinstance(cves, list):
                for cve in cves:
                    out_vuln.write(f"  - {cve}\n")
            elif isinstance(cves, dict):
                for cve_id, details in cves.items():
                    summary = details.get("summary", "No summary")
                    cvss = details.get("cvss", "N/A")
                    epss = details.get("epss", "N/A")
                    references = details.get("references", [])
                    out_vuln.write(f"  - {cve_id} | CVSS: {cvss} | EPSS: {epss}\n")
                    out_vuln.write(f"      Summary: {summary}\n")
                    for ref in references:
                        out_vuln.write(f"      Reference: {ref}\n")
        else:
            non_vulnerable_count += 1
            out_nonvuln.write(f"IP: {ip} | Type: {product_type} | Product: {product_name} {version}\n")

    # Summary for vulnerable products
    out_vuln.write("\n" + "="*50 + "\n")
    out_vuln.write(f"Total products: {total_products}\n")
    out_vuln.write(f"Vulnerable products: {vulnerable_count}\n")
    out_vuln.write(f"Non-vulnerable products: {non_vulnerable_count}\n")
    out_vuln.write("="*50 + "\n")

print(f"Vulnerable report written to {vuln_file}")
print(f"Non-vulnerable report written to {non_vuln_file}")