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
import shutil
import subprocess
import sys
import threading
from pathlib import Path

# ─── Discovery caches (avoid re-spawning CLI on every scan) ───────
_fw_cache: dict[str, list[str]] = {}
_svc_cache: dict[str, list[str]] = {}


# ─── Prowler executable resolution ────────────────────────────────

def _get_prowler_cmd() -> str:
    """
    Return the absolute path to the ``prowler`` executable.

    Strategy (in order):
      1. ``sys.prefix + /bin/prowler`` — works inside a venv (sys.prefix
         points at the venv root, *not* the system Python).
      2. Unresolved ``sys.executable`` parent — the directory of the
         interpreter **without** following symlinks, so it stays inside
         the venv ``bin/``.
      3. ``shutil.which("prowler")`` — searches the current PATH.
      4. Bare ``"prowler"`` — last resort.
    """
    # 1. venv root via sys.prefix (most reliable for venvs)
    venv_bin_prefix = Path(sys.prefix) / "bin" / "prowler"
    if venv_bin_prefix.is_file():
        return str(venv_bin_prefix)

    # 2. Unresolved parent of sys.executable (don't follow symlinks)
    exe_parent = Path(sys.executable).parent  # no .resolve()!
    candidate = exe_parent / "prowler"
    if candidate.is_file():
        return str(candidate)

    # 3. shutil.which — searches PATH
    which_result = shutil.which("prowler")
    if which_result:
        return which_result

    return "prowler"  # fall back to bare name


# ─── Prowler availability ─────────────────────────────────────────

_prowler_check_error: str = ""   # stores stderr from the last availability check

def _prowler_available() -> bool:
    """Check if the prowler CLI is installed and reachable.

    Strategy:
      1. Quick file-existence check (instant).
      2. ``prowler --version`` with a generous 120 s timeout — prowler is
         a large Python package and cold-starts can take 30-60 s.
    """
    global _prowler_check_error
    _prowler_check_error = ""
    try:
        cmd = _get_prowler_cmd()
        # Fast path: if the file simply doesn't exist, fail immediately
        if not Path(cmd).is_file() and not shutil.which(cmd):
            _prowler_check_error = f"prowler binary not found at {cmd}"
            return False

        r = subprocess.run(
            [cmd, "--version"],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            _prowler_check_error = r.stderr[:500] or r.stdout[:500] or f"exit code {r.returncode}"
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        # Prowler took too long but the binary exists — assume it works
        _prowler_check_error = "version check timed out (120 s) — proceeding anyway"
        return True
    except Exception as e:
        _prowler_check_error = str(e)[:300]
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
            [_get_prowler_cmd(), provider, "--list-compliance", "--no-banner"],
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
    Tries the Python import first, falls back to the CLI.  Results cached.
    """
    if provider in _fw_cache:
        if log_cb:
            log_cb(f"  Prowler {provider}: {len(_fw_cache[provider])} frameworks (cached)")
        return _fw_cache[provider]
    frameworks = _discover_frameworks_python(provider)
    if not frameworks:
        frameworks = _discover_frameworks_cli(provider)
    frameworks = sorted(set(frameworks))
    _fw_cache[provider] = frameworks
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
            [_get_prowler_cmd(), provider, "--list-services", "--no-banner"],
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
    """Discover every service prowler can scan for *provider*.  Results cached."""
    if provider in _svc_cache:
        if log_cb:
            log_cb(f"  Prowler {provider}: {len(_svc_cache[provider])} services (cached)")
        return _svc_cache[provider]
    services = _discover_services_python(provider)
    if not services:
        services = _discover_services_cli(provider)
    _svc_cache[provider] = services
    if log_cb:
        log_cb(f"  Prowler {provider}: {len(services)} services available")
    return services


def validate_services(
    user_services: list[str],
    available: list[str],
    log_cb=None,
) -> list[str]:
    """Return only user-selected services that actually exist in prowler.

    Deduplicates the input list so the same service isn't scanned twice.
    """
    seen: set[str] = set()
    valid: list[str] = []
    for svc in user_services:
        svc_lower = svc.strip().lower()
        if svc_lower in seen:
            if log_cb:
                log_cb(f"    service '{svc_lower}' — duplicate (skipped)")
            continue
        seen.add(svc_lower)
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
    aws_frameworks: list[str] | None = None,
    azure_frameworks: list[str] | None = None,
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

    Framework arguments:
      - *aws_frameworks*: Direct Prowler framework IDs for AWS (e.g. ``["cis_5.0_aws"]``)
      - *azure_frameworks*: Direct Prowler framework IDs for Azure (e.g. ``["cis_5.0_azure"]``)
      - *compliance_frameworks*: Legacy generic keys (used as fallback for keyword matching)

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
        prowler_path = _get_prowler_cmd()
        detail = _prowler_check_error or "unknown reason"
        msg = (
            f"Prowler CLI not working (path: {prowler_path}). "
            f"Reason: {detail}. "
            f"sys.prefix={sys.prefix}, sys.executable={sys.executable}. "
            f"Make sure prowler is installed: pip install prowler"
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

    # ── Prepare scan arguments per provider (before launching threads) ──

    def _prepare_aws():
        if log_callback:
            log_callback("Discovering AWS compliance frameworks & services...")
        available_aws_fw = discover_compliance_frameworks("aws", log_callback)
        available_aws_svc = discover_services("aws", log_callback)

        valid_aws_svc: list[str] = []
        if scan_opts["services"]:
            if log_callback:
                log_callback("Validating AWS services:")
            valid_aws_svc = validate_services(
                scan_opts["services"], available_aws_svc, log_callback,
            )

        # Use direct framework IDs if provided; fall back to legacy keyword matching
        aws_fw: list[str] = []
        if aws_frameworks:
            # Direct Prowler framework IDs from the frontend
            aws_fw = [f for f in aws_frameworks if f in available_aws_fw]
            skipped = [f for f in aws_frameworks if f not in available_aws_fw]
            if log_callback:
                log_callback(f"  AWS frameworks selected: {aws_fw}")
                for s in skipped:
                    log_callback(f"    '{s}' — not available in this prowler version (skipped)")
        elif compliance_frameworks and available_aws_fw:
            if log_callback:
                log_callback("Cross-checking user selections against AWS frameworks:")
            aws_fw = match_frameworks(
                compliance_frameworks, available_aws_fw, "aws", log_callback,
            )

        if valid_aws_svc and aws_fw:
            if log_callback:
                log_callback(
                    "  ⚠ --service and --compliance are mutually exclusive; "
                    "using --service (targeted scan) — compliance filter skipped"
                )
            aws_fw = []

        if log_callback:
            if valid_aws_svc:
                log_callback(f"  → AWS services: {valid_aws_svc}")
            elif aws_fw:
                log_callback(f"  → AWS compliance frameworks: {aws_fw}")
            else:
                log_callback("  → scanning ALL AWS checks (no filter)")
        return aws_fw, valid_aws_svc

    def _prepare_azure():
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

        # Use direct framework IDs if provided; fall back to legacy keyword matching
        az_fw: list[str] = []
        if azure_frameworks:
            az_fw = [f for f in azure_frameworks if f in available_az_fw]
            skipped = [f for f in azure_frameworks if f not in available_az_fw]
            if log_callback:
                log_callback(f"  Azure frameworks selected: {az_fw}")
                for s in skipped:
                    log_callback(f"    '{s}' — not available in this prowler version (skipped)")
        elif compliance_frameworks and available_az_fw:
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
        return az_fw, valid_az_svc

    # Prepare arguments (fast — only discovery calls)
    aws_scan_args = None
    azure_scan_args = None
    if aws_creds:
        aws_scan_args = _prepare_aws()
    if azure_creds:
        azure_scan_args = _prepare_azure()

    # ── Run AWS + Azure scans in parallel ─────────────────────────
    aws_holder: dict = {}
    azure_holder: dict = {}

    def _run_aws():
        aws_fw, valid_aws_svc = aws_scan_args
        aws_out = os.path.join(output_dir, "aws")
        os.makedirs(aws_out, exist_ok=True)
        if log_callback:
            log_callback("Starting Prowler AWS scan...")
        try:
            aws_holder["result"] = _scan_aws(
                aws_creds, aws_out, aws_fw, valid_aws_svc, scan_opts, log_callback,
            )
        except Exception as e:
            if log_callback:
                log_callback(f"  AWS scan thread error: {str(e)[:300]}")
            aws_holder["result"] = {
                "success": False, "findings": [], "finding_count": 0,
                "message": f"AWS scan error: {str(e)[:300]}",
            }

    def _run_azure():
        az_fw, valid_az_svc = azure_scan_args
        az_out = os.path.join(output_dir, "azure")
        os.makedirs(az_out, exist_ok=True)
        if log_callback:
            log_callback("Starting Prowler Azure scan...")
        try:
            azure_holder["result"] = _scan_azure(
                azure_creds, az_out, az_fw, valid_az_svc, scan_opts, log_callback,
            )
        except Exception as e:
            if log_callback:
                log_callback(f"  Azure scan thread error: {str(e)[:300]}")
            azure_holder["result"] = {
                "success": False, "findings": [], "finding_count": 0,
                "message": f"Azure scan error: {str(e)[:300]}",
            }

    threads: list[threading.Thread] = []
    if aws_creds and aws_scan_args:
        t = threading.Thread(target=_run_aws, daemon=True)
        threads.append(t)
    if azure_creds and azure_scan_args:
        t = threading.Thread(target=_run_azure, daemon=True)
        threads.append(t)

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if "result" in aws_holder:
        results["aws"] = aws_holder["result"]
        if aws_holder["result"].get("findings"):
            all_findings.extend(aws_holder["result"]["findings"])
    if "result" in azure_holder:
        results["azure"] = azure_holder["result"]
        if azure_holder["result"].get("findings"):
            all_findings.extend(azure_holder["result"]["findings"])

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

    cmd = [_get_prowler_cmd(), "aws", "-M", "json-ocsf", "-o", output_dir, "--no-banner"]

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

    # Region filter — also set AWS_DEFAULT_REGION so prowler knows the region
    if scan_opts.get("regions"):
        cmd.extend(["-f"] + scan_opts["regions"])
        if "AWS_DEFAULT_REGION" not in env:
            env["AWS_DEFAULT_REGION"] = scan_opts["regions"][0]

    # If no region specified anywhere, default to us-east-1 so prowler
    # doesn't silently skip scanning due to a missing region.
    if "AWS_DEFAULT_REGION" not in env:
        env["AWS_DEFAULT_REGION"] = "us-east-1"

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
        _get_prowler_cmd(), "azure", "--sp-env-auth",
        "-M", "json-ocsf", "-o", output_dir, "--no-banner",
    ]

    # Pass subscription-id explicitly if provided
    if creds.get("subscription_id"):
        cmd.extend(["--subscription-id", creds["subscription_id"]])

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
    import time as _time
    t0 = _time.monotonic()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, env=env, timeout=1800,
        )
        elapsed = _time.monotonic() - t0
        if log_cb:
            log_cb(f"  prowler finished in {elapsed:.1f}s (exit code {result.returncode})")
        if log_cb and result.stdout:
            for line in result.stdout.strip().splitlines()[-15:]:
                log_cb(f"  prowler[stdout]: {line}")
        if log_cb and result.stderr:
            stderr_lines = result.stderr.strip().splitlines()
            # Log more stderr for diagnosis — auth failures appear here
            for line in stderr_lines[-30:]:
                log_cb(f"  prowler[stderr]: {line}")

        # If prowler finished in under 10 seconds, it likely failed to authenticate
        if elapsed < 10 and log_cb:
            log_cb(f"  ⚠ {label}: Scan completed in {elapsed:.1f}s — suspiciously fast. "
                   f"Check credentials and ensure the cloud account has resources.")

        # Detect common auth failures in stderr
        stderr_lower = (result.stderr or "").lower()
        auth_error = False
        for pattern in ("invalidclienttokenid", "signaturedoesnotmatch",
                        "accessdenied", "authorizationerror", "expiredtoken",
                        "invalid credential", "could not connect",
                        "unable to locate credentials", "no credentials"):
            if pattern in stderr_lower:
                auth_error = True
                if log_cb:
                    log_cb(f"  ⚠ {label}: Possible authentication failure detected in stderr")
                break

        # Locate output JSON.
        # Prowler writes output into subdirectories under -o, e.g.
        # <output_dir>/compliance/<filename>.ocsf.json  or a timestamped
        # subfolder.  We search recursively.
        # Prowler writes to nested dirs, find ALL json output
        all_json = sorted(Path(output_dir).rglob("*.json"))
        if log_cb:
            log_cb(f"  {label}: found {len(all_json)} JSON files in output dir")
            for jf in all_json[:10]:
                log_cb(f"    → {jf.relative_to(output_dir)} ({jf.stat().st_size} bytes)")

        # Prefer .ocsf.json, then regular .json
        json_files = sorted(p for p in all_json if p.name.endswith(".ocsf.json"))
        if not json_files:
            json_files = sorted(
                p for p in all_json
                if p.stat().st_size > 10  # skip empty/stub files
                and "combined" not in p.name
                and "prowler_findings" not in p.name
            )
        if not json_files:
            csv_files = sorted(Path(output_dir).rglob("*.csv"))
            if csv_files and log_cb:
                log_cb(f"  {label}: Found CSV output but no JSON — check prowler -M flag")

        if json_files:
            # Load ALL json files (prowler may split output across multiple files)
            all_findings = []
            for jf in json_files:
                try:
                    with open(jf) as f:
                        data = json.load(f)
                    if isinstance(data, dict):
                        data = data.get("findings", [data])
                    if isinstance(data, list):
                        all_findings.extend(data)
                    if log_cb:
                        log_cb(f"  {label}: loaded {len(data) if isinstance(data, list) else 1} findings from {jf.name}")
                except Exception as e:
                    if log_cb:
                        log_cb(f"  {label}: failed to parse {jf.name}: {str(e)[:100]}")

            if log_cb:
                log_cb(
                    f"  {label} scan produced {len(all_findings)} findings"
                    f" from {len(json_files)} file(s)"
                )
            return {
                "success": True,
                "finding_count": len(all_findings),
                "findings": all_findings,
                "output_file": str(json_files[-1]),
                "message": f"{label} scan complete — {len(all_findings)} findings",
            }

        if log_cb:
            log_cb(f"  {label}: no JSON output file found in {output_dir}")
            # List what IS in the directory to aid debugging
            try:
                all_files = list(Path(output_dir).rglob("*"))
                file_names = [str(f.relative_to(output_dir)) for f in all_files if f.is_file()]
                dir_names = [str(f.relative_to(output_dir)) for f in all_files if f.is_dir()]
                log_cb(f"  {label}: output dir files: {file_names}")
                log_cb(f"  {label}: output dir dirs: {dir_names}")
            except Exception:
                log_cb(f"  {label}: could not list output dir contents")
            if auth_error:
                log_cb(f"  {label}: No output likely due to credential/auth failure — check your {label} credentials")

        return {
            "success": not auth_error,
            "finding_count": 0,
            "findings": [],
            "message": (
                f"{label}: Authentication failure — check credentials"
                if auth_error
                else f"{label} scan completed — no JSON output file found"
            ),
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
