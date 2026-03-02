#!/usr/bin/env python3
"""Download compliance PDF documents from the reference repo."""
import os, urllib.request, sys

DOCS_DIR = os.path.join(os.path.dirname(__file__), "docs")
BASE_URL = "https://raw.githubusercontent.com/devjoshi2005/Grc-Compliance-Engine/main/docs"

PDFS = [
    "NIST.SP.800-53r5.pdf",
    "PCI-DSS-v4_0_1.pdf",
    "NIST_ISO_MAPPING.pdf",
    "CIS_AWS_Foundations.pdf",
]

os.makedirs(DOCS_DIR, exist_ok=True)
for name in PDFS:
    dest = os.path.join(DOCS_DIR, name)
    if os.path.exists(dest) and os.path.getsize(dest) > 1000:
        print(f"  SKIP  {name} (already exists)")
        continue
    url = f"{BASE_URL}/{name}"
    print(f"  GET   {url}")
    try:
        urllib.request.urlretrieve(url, dest)
        sz = os.path.getsize(dest)
        print(f"  OK    {name} ({sz:,} bytes)")
    except Exception as e:
        print(f"  FAIL  {name}: {e}", file=sys.stderr)

print("\ndocs/ contents:")
for f in sorted(os.listdir(DOCS_DIR)):
    sz = os.path.getsize(os.path.join(DOCS_DIR, f))
    print(f"  {sz:>12,}  {f}")
