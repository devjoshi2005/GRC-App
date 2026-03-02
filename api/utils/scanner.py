"""Prowler scanner integration.

Dynamically discovers supported compliance frameworks and services at runtime
via prowler's Python API or CLI fallback.  User-facing framework keys and
service names are cross-checked against the live list, filtered, and only
valid values are passed to the scan command.

Supports resource-scoping options:
  - **services**: Only scan specific services (e.g., s3, iam, ec2)
  - **resource_tags**: Only scan resources matching Key=Value tags (AWS only)
  - **resource_arns**: Only scan specific ARNs (AWS only)
  - **severity**: Only include findings at certain severity levels
  - **regions**: Limit scan to specific regions (AWS only)
  - **excluded_services**: Skip certain services

NOTE: ``--service`` and ``--compliance`` are **mutually exclusive** in
prowler's argparse.  When the user selects BOTH services and compliance,
we use ``--service`` (faster targeted scan) and log a note.
"""

import json
import os
import re
import subprocess
from pathlib import Path


# ─── Prowler availability ─────────────────────────────────────────

def _prowler_available() -> bool:
    """Check if the prowler CLI is installed and reachable."""
    try:
        r = subprocess.run(
            ["prowler", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


# ─── Dynamic Compliance Discovery ─────────────────────────────────

def _discover_frameworks_python(provider: str) -> list[str]:
    """Use prowler's Python API directly — fastest, no subprocess."""
    try:
        from prowler.config.config import get_available_compliance_frameworks
        return get_available_compliance_frameworks(provider)
    except Exception:
        return []


def _discover_frameworks_cli(provider: str) -> list[str]:
    """Fallback: ``prowler <provider> --list-compliance --no-banner``."""
    try:
        result = subprocess.run(
            ["prowler", provider, "--list-compliance", "--no-banner"],
            capture_output=True, text=True, timeout=60,
        )
        frameworks = []
        for line in result.stdout.splitlines():
            name = line.strip().lstrip("- ").strip()
            # Skip empty lines, header text, summary lines
            if name and not name.startswith("There ") and "_" in name:
                frameworks.append(name)
        return frameworks
    except Exception:
        return []


def discover_compliance_frameworks(provider: str, log_cb=None) -> list[str]:
    """
    Discover every compliance framework prowler supports for *provider*.
    Tries the Python import first, falls back to the CLI.
    """
    frameworks = _discover_frameworks_python(provider)
    if not frameworks:
        frameworks = _discover_frameworks_cli(provider)
    frameworks = sorted(set(frameworks))
    if log_cb:
        log_cb(
            f"  Prowler {provider}: {len(frameworks)} compliance frameworks available"
        )
    return frameworks


# ─── Dynamic Service Discovery ────────────────────────────────────

def _discover_services_python(provider: str) -> list[str]:
    """Use prowler's Python API to list scannable services."""
    try:
        from prowler.lib.check.check import list_services
        return sorted(list_services(provider))
    except Exception:
        return []


def _discover_services_cli(provider: str) -> list[str]:
    """Fallback: ``prowler <provider> --list-services --no-banner``."""
    try:
        result = subprocess.run(
            ["prowler", provider, "--list-services", "--no-banner"],
            capture_output=True, text=True, timeout=60,
        )
        services = []
        for line in result.stdout.splitlines():
            name = line.strip().lstrip("- ").strip()
            if name and not name.startswith(("Available", "There ", "Listing")):
                services.append(name)
        return sorted(set(services))
    except Exception:
        return []


def discover_services(provider: str, log_cb=None) -> list[str]:
    """Discover every service prowler can scan for *provider*."""
    services = _discover_services_python(provider)
    if not services:
        services = _discover_services_cli(provider)
    if log_cb:
        log_cb(f"  Prowler {provider}: {len(services)} services available")
    return services


def validate_services(
    user_services: list[str],
    available: list[str],
    log_cb=None,
) -> list[str]:
    """Return only user-selected services that actually exist in prowler."""
    valid = []
    for svc in user_services:
        svc_lower = svc.strip().lower()
        if svc_lower in available:
            valid.append(svc_lower)
            if log_cb:
                log_cb(f"    service '{svc_lower}' ✓")
        else:
            if log_cb:
                log_cb(f"    service '{svc_lower}' — not available (skipped)")
    return valid


# ─── User-Selection → Prowler Framework Matching ──────────────────

# Each user-facing key maps to a regex that matches one or more prowler
# framework IDs.  When multiple versions match (e.g. cis_1.4_aws …
# cis_5.0_aws) we pick the *latest* (alphabetically last).
_KEYWORD_PATTERNS: dict[str, str] = {
    "pci_dss":          r"pci_",
    "hipaa":            r"hipaa_",
    "cis_aws":          r"cis_[\d.]+_aws$",
    "cis_azure":        r"cis_[\d.]+_azure$",
    "cis_gcp":          r"cis_[\d.]+_gcp$",
    "nist_800_53":      r"nist_800_53_",
    "nist_800_171":     r"nist_800_171_",
    "nist_csf":         r"nist_csf_",
    "soc2":             r"soc2_",
    "gdpr":             r"gdpr_",
    "fedramp":          r"fedramp_",
    "iso_27001":        r"iso27001_",
    "mitre_attack":     r"mitre_attack_",
    "ens":              r"ens_",
    "cisa":             r"cisa_",
    "ffiec":            r"ffiec_",
    "aws_waf":          r"aws_foundational_security",
    "azure_security":   r"azure_security",
    "csa_ccm":          r"csa_ccm_",
    "cis_docker":       r"cis_[\d.]+_docker",
    "cis_kubernetes":   r"cis_[\d.]+_kubernetes",
    "glba":             r"glba_",
    "cmmc":             r"cmmc_",
    "sox":              r"sox_",
    "ccpa":             r"ccpa_",
    "fisma":            r"fisma_",
    "ferpa":            r"ferpa_",
    "nist_iso_mapping": r"nist_iso_mapping",
}


def _pick_latest(matches: list[str]) -> str:
    """Among multiple framework matches (different versions), return the latest."""
    return sorted(matches)[-1]


def match_frameworks(
    user_selections: list[str],
    available: list[str],
    provider: str,
    log_cb=None,
) -> list[str]:
    """
    Cross-check user framework selections against the **actually available**
    prowler frameworks for *provider*.

    Returns a deduplicated list of valid prowler framework IDs.
    """
    suffix = f"_{provider}"
    provider_available = [f for f in available if f.endswith(suffix)]

    matched: list[str] = []
    for key in user_selections:
        pattern = _KEYWORD_PATTERNS.get(key)
        if pattern:
            hits = [f for f in provider_available if re.search(pattern, f)]
        else:
            # Fallback: substring match
            hits = [f for f in provider_available if key in f]

        if hits:
            best = _pick_latest(hits)
            if best not in matched:
                matched.append(best)
                if log_cb:
                    log_cb(f"    '{key}' → {best}")
        else:
            if log_cb:
                log_cb(f"    '{key}' — no matching {provider} framework (skipped)")

    return matched


# ─── Main Scan Orchestrator ───────────────────────────────────────

def run_prowler_scan(
    aws_creds: dict | None,
    azure_creds: dict | None,
    output_dir: str,
    compliance_frameworks: list[str] | None = None,
    services: list[str] | None = None,
    resource_tags: list[str] | None = None,
    resource_arns: list[str] | None = None,
    severity: list[str] | None = None,
    regions: list[str] | None = None,
    excluded_services: list[str] | None = None,
    log_callback=None,
) -> dict:
    """
    Orchestrate real Prowler scans for AWS and/or Azure.

    Scan-scope arguments (all optional):
      - *services*: Only scan these services  (e.g. ``["s3","iam","ec2"]``)
      - *resource_tags*: AWS only ``["Key=Value", ...]``
      - *resource_arns*: AWS only ``["arn:aws:...", ...]``
      - *severity*: ``["critical","high","medium","low"]``
      - *regions*: AWS ``["us-east-1","eu-west-1"]``
      - *excluded_services*: Skip these services

    Flow:
      1. Check prowler is installed.
      2. Dynamically discover frameworks / services.
      3. Cross-check & validate user selections.
      4. Build CLI command with only valid flags.

    NOTE: ``--service`` and ``--compliance`` are **mutually exclusive** in
    prowler.  When the user selects services, ``--service`` takes priority
    (because narrowing services is the whole point of speeding up scans).
    ``--resource-tags``, ``--severity``, ``--excluded-services`` all work
    alongside ``--compliance`` or ``--service``.

    Returns ``{"aws": {...}, "azure": {...}, "combined_file": path,
               "total_findings": int}``.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    results: dict = {"aws": None, "azure": None, "combined_file": None}
    all_findings: list = []

    if not _prowler_available():
        msg = (
            "Prowler CLI not found. Install with: pip install prowler\n"
            "See https://docs.prowler.com/projects/prowler-open-source/en/latest/"
        )
        if log_callback:
            log_callback(f"ERROR: {msg}")
        return {
            "aws": None, "azure": None, "combined_file": None,
            "total_findings": 0, "error": msg,
        }

    if log_callback:
        log_callback("Prowler CLI detected — starting real cloud scans")

    # ── Shared scan-scope context ─────────────────────────────────
    scan_opts: dict = {
        "services": services or [],
        "resource_tags": resource_tags or [],
        "resource_arns": resource_arns or [],
        "severity": [s.lower() for s in (severity or [])],
        "regions": regions or [],
        "excluded_services": excluded_services or [],
    }

    # ── AWS ────────────────────────────────────────────────────────
    if aws_creds:
        if log_callback:
            log_callback("Discovering AWS compliance frameworks & services...")
        available_aws_fw = discover_compliance_frameworks("aws", log_callback)
        available_aws_svc = discover_services("aws", log_callback)

        # Validate services
        valid_aws_svc: list[str] = []
        if scan_opts["services"]:
            if log_callback:
                log_callback("Validating AWS services:")
            valid_aws_svc = validate_services(
                scan_opts["services"], available_aws_svc, log_callback,
            )

        # Validate compliance frameworks
        aws_fw: list[str] = []
        if compliance_frameworks and available_aws_fw:
            if log_callback:
                log_callback("Cross-checking user selections against AWS frameworks:")
            aws_fw = match_frameworks(
                compliance_frameworks, available_aws_fw, "aws", log_callback,
            )

        # Log strategy
        if valid_aws_svc and aws_fw:
            if log_callback:
                log_callback(
                    "  ⚠ --service and --compliance are mutually exclusive; "
                    "using --service (targeted scan) — compliance filter skipped"
                )
            aws_fw = []  # service takes priority

        if log_callback:
            if valid_aws_svc:
                log_callback(f"  → AWS services: {valid_aws_svc}")
            elif aws_fw:
                log_callback(f"  → AWS compliance frameworks: {aws_fw}")
            else:
                log_callback("  → scanning ALL AWS checks (no filter)")
            log_callback("Starting Prowler AWS scan...")

        aws_result = _scan_aws(
            aws_creds, output_dir, aws_fw, valid_aws_svc, scan_opts, log_callback,
        )
        results["aws"] = aws_result
        if aws_result.get("findings"):
            all_findings.extend(aws_result["findings"])

    # ── Azure ─────────────────────────────────────────────────────
    if azure_creds:
        if log_callback:
            log_callback("Discovering Azure compliance frameworks & services...")
        available_az_fw = discover_compliance_frameworks("azure", log_callback)
        available_az_svc = discover_services("azure", log_callback)

        valid_az_svc: list[str] = []
        if scan_opts["services"]:
            if log_callback:
                log_callback("Validating Azure services:")
            valid_az_svc = validate_services(
                scan_opts["services"], available_az_svc, log_callback,
            )

        az_fw: list[str] = []
        if compliance_frameworks and available_az_fw:
            if log_callback:
                log_callback("Cross-checking user selections against Azure frameworks:")
            az_fw = match_frameworks(
                compliance_frameworks, available_az_fw, "azure", log_callback,
            )

        if valid_az_svc and az_fw:
            if log_callback:
                log_callback(
                    "  ⚠ --service and --compliance are mutually exclusive; "
                    "using --service — compliance filter skipped"
                )
            az_fw = []

        if log_callback:
            if valid_az_svc:
                log_callback(f"  → Azure services: {valid_az_svc}")
            elif az_fw:
                log_callback(f"  → Azure compliance frameworks: {az_fw}")
            else:
                log_callback("  → scanning ALL Azure checks (no filter)")
            log_callback("Starting Prowler Azure scan...")

        az_result = _scan_azure(
            azure_creds, output_dir, az_fw, valid_az_svc, scan_opts, log_callback,
        )
        results["azure"] = az_result
        if az_result.get("findings"):
            all_findings.extend(az_result["findings"])

    # ── Combined output ───────────────────────────────────────────
    combined_path = os.path.join(output_dir, "prowler_combined_findings.json")
    with open(combined_path, "w") as f:
        json.dump(all_findings, f, indent=2, default=str)
    results["combined_file"] = combined_path
    results["total_findings"] = len(all_findings)

    if log_callback:
        log_callback(f"Prowler scan complete — {len(all_findings)} total findings")

    return results


# ─── AWS Scan ─────────────────────────────────────────────────────

def _scan_aws(
    creds: dict,
    output_dir: str,
    prowler_frameworks: list[str],
    prowler_services: list[str],
    scan_opts: dict,
    log_cb,
) -> dict:
    """Run ``prowler aws`` with pre-validated compliance/service/tag filters."""
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = creds["access_key_id"]
    env["AWS_SECRET_ACCESS_KEY"] = creds["secret_access_key"]
    if creds.get("session_token"):
        env["AWS_SESSION_TOKEN"] = creds["session_token"]
    if creds.get("region"):
        env["AWS_DEFAULT_REGION"] = creds["region"]

    cmd = ["prowler", "aws", "-M", "json-ocsf", "-o", output_dir, "--no-banner"]

    # --service and --compliance are mutually exclusive (argparse)
    if prowler_services:
        cmd.extend(["--service"] + prowler_services)
    elif prowler_frameworks:
        cmd.extend(["--compliance"] + prowler_frameworks)

    # Resource-tags — works with both --service and --compliance (separate group)
    if scan_opts.get("resource_tags"):
        cmd.extend(["--resource-tags"] + scan_opts["resource_tags"])

    # Resource-ARNs — works with both (separate group, mutually exclusive with tags)
    elif scan_opts.get("resource_arns"):
        cmd.extend(["--resource-arn"] + scan_opts["resource_arns"])

    # Severity — works with everything
    if scan_opts.get("severity"):
        cmd.extend(["--severity"] + scan_opts["severity"])

    # Region filter
    if scan_opts.get("regions"):
        cmd.extend(["-f"] + scan_opts["regions"])

    # Excluded services — works with everything
    if scan_opts.get("excluded_services"):
        cmd.extend(["--excluded-services"] + scan_opts["excluded_services"])

    if log_cb:
        log_cb(f"  cmd: {' '.join(cmd)}")

    return _exec_prowler(cmd, env, output_dir, "AWS", log_cb)


# ─── Azure Scan ───────────────────────────────────────────────────

def _scan_azure(
    creds: dict,
    output_dir: str,
    prowler_frameworks: list[str],
    prowler_services: list[str],
    scan_opts: dict,
    log_cb,
) -> dict:
    """Run ``prowler azure --sp-env-auth`` with pre-validated filters."""
    env = os.environ.copy()
    env["AZURE_CLIENT_ID"] = creds["client_id"]
    env["AZURE_TENANT_ID"] = creds["tenant_id"]
    env["AZURE_CLIENT_SECRET"] = creds["client_secret"]
    if creds.get("subscription_id"):
        env["AZURE_SUBSCRIPTION_ID"] = creds["subscription_id"]

    cmd = [
        "prowler", "azure", "--sp-env-auth",
        "-M", "json-ocsf", "-o", output_dir, "--no-banner",
    ]

    if prowler_services:
        cmd.extend(["--service"] + prowler_services)
    elif prowler_frameworks:
        cmd.extend(["--compliance"] + prowler_frameworks)

    # Severity
    if scan_opts.get("severity"):
        cmd.extend(["--severity"] + scan_opts["severity"])

    # Excluded services
    if scan_opts.get("excluded_services"):
        cmd.extend(["--excluded-services"] + scan_opts["excluded_services"])

    # Note: --resource-tags and --resource-arn are AWS-only flags

    if log_cb:
        log_cb(f"  cmd: {' '.join(cmd)}")

    return _exec_prowler(cmd, env, output_dir, "Azure", log_cb)


# ─── Shared execution helper ─────────────────────────────────────

def _exec_prowler(
    cmd: list[str],
    env: dict,
    output_dir: str,
    label: str,
    log_cb,
) -> dict:
    """Execute a prowler command and collect JSON output findings."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, env=env, timeout=1800,
        )
        if log_cb and result.stdout:
            for line in result.stdout.strip().splitlines()[-10:]:
                log_cb(f"  prowler[stdout]: {line}")
        if log_cb and result.stderr:
            for line in result.stderr.strip().splitlines()[-20:]:
                log_cb(f"  prowler[stderr]: {line}")
        if log_cb and result.returncode != 0:
            log_cb(f"  prowler exit code: {result.returncode}")

        # Locate output JSON.
        # Prowler writes <output_dir>/<filename>.ocsf.json
        json_files = sorted(Path(output_dir).glob("*.ocsf.json"))
        if not json_files:
            json_files = sorted(
                p for p in Path(output_dir).glob("*.json")
                if "combined" not in p.name
            )

        if json_files:
            with open(json_files[-1]) as f:
                findings = json.load(f)
            if isinstance(findings, dict):
                # Some prowler versions wrap in {"findings": [...]}
                findings = findings.get("findings", [findings])
            if log_cb:
                log_cb(
                    f"  {label} scan produced {len(findings)} findings"
                    f" → {json_files[-1].name}"
                )
            return {
                "success": True,
                "finding_count": len(findings),
                "findings": findings,
                "output_file": str(json_files[-1]),
                "message": f"{label} scan complete — {len(findings)} findings",
            }

        if log_cb:
            log_cb(f"  {label}: no JSON output file found in {output_dir}")
            # List what IS in the directory to aid debugging
            contents = list(Path(output_dir).iterdir())
            log_cb(f"  {label}: output dir contents: {[c.name for c in contents]}")

        return {
            "success": True,
            "finding_count": 0,
            "findings": [],
            "message": f"{label} scan completed — no JSON output file found",
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False, "findings": [],
            "message": f"{label} scan timed out (30 min limit)",
        }
    except Exception as e:
        return {
            "success": False, "findings": [],
            "message": f"{label} scan error: {str(e)[:500]}",
        }
