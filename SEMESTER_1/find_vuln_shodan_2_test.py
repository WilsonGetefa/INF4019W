#!/usr/bin/env python3
import json

file_path = "product_cpes_cves_with_ip.json"

def load_json_objects(file_path):
    objects = []
    with open(file_path, "r") as f:
        content = f.read().strip()
    # Split by '}{' if JSON is not in array format
    parts = content.replace("}\n{", "}|||{").split("|||")
    for part in parts:
        try:
            obj = json.loads(part)
            objects.append(obj)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
    return objects

data = load_json_objects(file_path)

# Check for IP or ip_str
found_ip = False
for i, product in enumerate(data, 1):
    print(f"\nObject #{i}:")
    keys = list(product.keys())
    print(f"Keys: {keys}")
    
    ip = product.get("ip") or product.get("ip_str")
    if ip:
        found_ip = True
        print(f"IP Found: {ip}")
    
    # Optional: print product info
    print(f"Product: {product.get('product', 'Unknown')}, Version: {product.get('version', 'Unknown')}")
    
if not found_ip:
    print("\nNo IP or ip_str fields found in any object.")