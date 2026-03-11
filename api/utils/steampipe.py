"""Steampipe-style extraction of columns from Prowler findings.
When Steampipe CLI is available, uses steampipe; otherwise parses JSON directly."""

import json
import csv
import io
import subprocess
from typing import Any


def extract_columns(
    findings: list[dict],
    columns: list[str],
    severity_filter: list[str] | None = None,
    log_callback=None,
) -> dict:
    """
    Extract user-specified columns from Prowler findings.
    Mimics Steampipe SQL query: SELECT col1, col2, ... FROM prowler_findings
    WHERE severity IN (...) AND status_code = 'FAIL'
    """
    if severity_filter is None:
        severity_filter = ["Critical", "High"]

    # Column mapping: user-friendly name → JSON path
    COLUMN_MAP = {
        "name": lambda f: _get_resource(f, "name"),
        "resource_name": lambda f: _get_resource(f, "name"),
        "uid": lambda f: _get_resource(f, "uid"),
        "arn": lambda f: _get_resource(f, "uid"),
        "resource_uid": lambda f: _get_resource(f, "uid"),
        "type": lambda f: _get_resource(f, "type"),
        "resource_type": lambda f: _get_resource(f, "type"),
        "region": lambda f: _get_resource(f, "region"),
        "tags": lambda f: json.dumps(_get_resource(f, "data", {}).get("metadata", {})),
        "severity": lambda f: f.get("severity", ""),
        "status": lambda f: f.get("status", ""),
        "status_code": lambda f: f.get("status_code", ""),
        "title": lambda f: f.get("finding_info", {}).get("title", ""),
        "description": lambda f: f.get("finding_info", {}).get("desc", ""),
        "risk": lambda f: f.get("risk_details", ""),
        "remediation": lambda f: f.get("remediation", {}).get("desc", ""),
        "event_code": lambda f: f.get("metadata", {}).get("event_code", ""),
        "check_id": lambda f: f.get("metadata", {}).get("event_code", ""),
        "provider": lambda f: f.get("cloud", {}).get("provider", ""),
        "account_id": lambda f: f.get("cloud", {}).get("account", {}).get("uid", ""),
        "publicly_accessible": lambda f: _check_public(f),
        "encryption_status": lambda f: _check_encryption(f),
        "compliance": lambda f: _get_compliance(f),
        "created_time": lambda f: f.get("finding_info", {}).get("created_time_dt", ""),
        "instance_type": lambda f: _get_resource(f, "type"),
    }

    # Filter findings — only require status_code=FAIL + severity match.
    # Do NOT filter on status=="New"; AWS findings may use different status values.
    filtered = [
        f for f in findings
        if f.get("status_code") == "FAIL"
        and f.get("severity") in severity_filter
    ]

    if log_callback:
        log_callback(f"Steampipe extraction: {len(filtered)}/{len(findings)} findings, {len(columns)} columns")

    # Extract data
    rows = []
    for finding in filtered:
        row = {}
        for col in columns:
            col_clean = col.strip().lower().replace(" ", "_")
            extractor = COLUMN_MAP.get(col_clean)
            if extractor:
                row[col.strip()] = extractor(finding)
            else:
                row[col.strip()] = _deep_search(finding, col_clean)
        rows.append(row)

    # Generate SQL-like summary
    sql_query = f"SELECT {', '.join(columns)}\nFROM prowler_findings\nWHERE severity IN ({', '.join(repr(s) for s in severity_filter)})\n  AND status_code = 'FAIL'"

    return {
        "success": True,
        "rows": rows,
        "row_count": len(rows),
        "columns": columns,
        "sql_query": sql_query,
        "message": f"Extracted {len(rows)} rows × {len(columns)} columns",
    }


def export_to_csv(extraction_result: dict) -> str:
    """Convert extraction result to Excel-compatible CSV string.

    Adds UTF-8 BOM for Excel auto-detection, sanitises multiline values,
    and forces quoting so commas inside fields don't break columns.
    """
    rows = extraction_result.get("rows", [])
    columns = extraction_result.get("columns", [])
    fieldnames = [c.strip() for c in columns]

    output = io.StringIO()
    # UTF-8 BOM so Excel opens the file with correct encoding
    output.write("\ufeff")

    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        quoting=csv.QUOTE_ALL,
        lineterminator="\r\n",
    )
    writer.writeheader()
    for row in rows:
        sanitised = {}
        for k, v in row.items():
            val = str(v) if v is not None else ""
            # Replace newlines/tabs that break Excel rows
            val = val.replace("\r\n", "; ").replace("\n", "; ").replace("\r", "; ").replace("\t", " ")
            sanitised[k] = val
        writer.writerow(sanitised)
    return output.getvalue()


# ─── Helper Functions ────────────────────────────────────────────

def _get_resource(finding: dict, key: str, default="") -> Any:
    resources = finding.get("resources", [{}])
    if resources:
        return resources[0].get(key, default)
    return default


def _check_public(finding: dict) -> str:
    """Determine if resource is publicly accessible from finding context."""
    title = finding.get("finding_info", {}).get("title", "").lower()
    event_code = finding.get("metadata", {}).get("event_code", "").lower()

    if any(x in title for x in ["public", "internet", "0.0.0.0"]):
        return "Yes"
    if any(x in event_code for x in ["public", "internet", "exposed"]):
        return "Yes"
    return "No"


def _check_encryption(finding: dict) -> str:
    """Check encryption status from finding context."""
    event_code = finding.get("metadata", {}).get("event_code", "").lower()
    title = finding.get("finding_info", {}).get("title", "").lower()

    if "encrypt" in event_code or "encrypt" in title:
        if finding.get("status_code") == "FAIL":
            return "Not Encrypted"
    return "Unknown"


def _get_compliance(finding: dict) -> str:
    """Get compliance framework mapping."""
    unmapped = finding.get("unmapped", {})
    compliance = unmapped.get("compliance", {}) if isinstance(unmapped, dict) else {}
    if isinstance(compliance, dict):
        parts = []
        for fw, controls in compliance.items():
            if controls:
                parts.append(f"{fw}: {', '.join(controls[:3])}")
        return "; ".join(parts[:3])
    return ""


def _deep_search(data: dict, key: str, depth: int = 3) -> str:
    """Recursively search for a key in nested dict."""
    if depth <= 0:
        return ""
    if key in data:
        val = data[key]
        return str(val) if not isinstance(val, (dict, list)) else json.dumps(val)
    for v in data.values():
        if isinstance(v, dict):
            result = _deep_search(v, key, depth - 1)
            if result:
                return result
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    result = _deep_search(item, key, depth - 1)
                    if result:
                        return result
    return ""
