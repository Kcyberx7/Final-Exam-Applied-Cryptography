import hashlib
import json

# --- Step 1: Create original file ---
original_file = "original.txt"
with open(original_file, "w") as f:
    f.write("This is a secure message for hashing integrity check.")

# --- Function to compute hashes ---
def compute_hashes(filename):
    hashes = {}
    with open(filename, "rb") as f:
        data = f.read()
        hashes['MD5'] = hashlib.md5(data).hexdigest()
        hashes['SHA1'] = hashlib.sha1(data).hexdigest()
        hashes['SHA256'] = hashlib.sha256(data).hexdigest()
    return hashes

# --- Step 2: Compute hashes for original file ---
hashes = compute_hashes(original_file)
with open("hashes.json", "w") as f:
    json.dump(hashes, f, indent=4)

print("Hashes for original.txt saved in hashes.json")

# --- Step 3: Simulate tampering ---
tampered_file = "tampered.txt"
with open(original_file, "r") as f:
    content = f.read()

tampered_content = content + "\nTampering added!"
with open(tampered_file, "w") as f:
    f.write(tampered_content)

# --- Step 4: Recompute hashes for tampered file ---
new_hashes = compute_hashes(tampered_file)

# --- Step 5: Check integrity ---
with open("hashes.json", "r") as f:
    original_hashes = json.load(f)

print("\nIntegrity Check Results:")
for algo in ['MD5', 'SHA1', 'SHA256']:
    if original_hashes[algo] == new_hashes[algo]:
        print(f"{algo}: PASS")
    else:
        print(f"{algo}: FAIL (file modified!)")
