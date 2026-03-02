#!/usr/bin/env python3
"""Check what compliance frameworks prowler supports for AWS and Azure."""
import subprocess, os
os.environ["TMPDIR"] = "/workspaces/GRC-App/.tmp"
os.makedirs("/workspaces/GRC-App/.tmp", exist_ok=True)

print("=== AWS COMPLIANCE FRAMEWORKS ===")
r1 = subprocess.run(
    ["prowler", "aws", "--list-compliance", "--no-banner"],
    capture_output=True, text=True, timeout=30
)
print("STDOUT:")
print(r1.stdout if r1.stdout else "(empty)")
if r1.stderr:
    print("STDERR (last 800 chars):")
    print(r1.stderr[-800:])
print(f"Return code: {r1.returncode}")

print("\n=== AZURE COMPLIANCE FRAMEWORKS ===")
r2 = subprocess.run(
    ["prowler", "azure", "--list-compliance", "--no-banner"],
    capture_output=True, text=True, timeout=30
)
print("STDOUT:")
print(r2.stdout if r2.stdout else "(empty)")
if r2.stderr:
    print("STDERR (last 800 chars):")
    print(r2.stderr[-800:])
print(f"Return code: {r2.returncode}")
