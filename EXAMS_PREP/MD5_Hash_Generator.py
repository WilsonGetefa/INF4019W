import hashlib

# The input string
print()
input_string = input("Please eneter the plaintext you want to hash using MD5: ")

# Encode the string to bytes, then create the MD5 hash
md5_hash = hashlib.md5(input_string.encode())

# Get the hexadecimal digest
hex_digest = md5_hash.hexdigest()

print(f"MD5 hash of '{input_string}' is: {hex_digest}")

"""
# The input string
print()
input_string = input("Please eneter the plaintext you want to hash using SHA-256: ")

# Encode the string to bytes, then create the SHA-256 hash
sha256_hash = hashlib.sha256(input_string.encode())

# Get the hexadecimal digest
hex_digest = sha256_hash.hexdigest()

print(f"SHA-256 hash of '{input_string}' is: {hex_digest}")
"""