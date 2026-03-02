#!/usr/bin/env bash
# Download compliance PDF documents from the reference GRC repo into docs/
set -e

REPO_BASE="https://raw.githubusercontent.com/devjoshi2005/Grc-Compliance-Engine/main/docs"
DOCS_DIR="$(dirname "$0")/docs"

mkdir -p "$DOCS_DIR"
cd "$DOCS_DIR"

echo "Downloading compliance documents..."

curl -sL -o "NIST.SP.800-53r5.pdf"   "$REPO_BASE/NIST.SP.800-53r5.pdf"
curl -sL -o "PCI-DSS-v4_0_1.pdf"     "$REPO_BASE/PCI-DSS-v4_0_1.pdf"
curl -sL -o "NIST_ISO_MAPPING.pdf"    "$REPO_BASE/NIST_ISO_MAPPING.pdf"
curl -sL -o "CIS_AWS_Foundations.pdf"  "$REPO_BASE/CIS_AWS_Foundations.pdf"

echo "Done. Downloaded $(ls -1 *.pdf | wc -l) PDFs:"
ls -lh *.pdf
