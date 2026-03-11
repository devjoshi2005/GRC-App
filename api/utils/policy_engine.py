"""OPA Rego policy validation engine.
Validates AI-generated Terraform code against security policies using:
  1. conftest (preferred) — runs Rego deny rules against .tf files
  2. trivy config — built-in misconfiguration scanning
  3. OPA eval — raw policy evaluation
  4. Python regex fallback — basic pattern checks
"""

import json
import os
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ─── Cached tool availability checks ─────────────────────────────
_opa_cache = None
_conftest_cache = None
_trivy_cache = None


def _opa_available() -> bool:
    global _opa_cache
    if _opa_cache is not None:
        return _opa_cache
    try:
        r = subprocess.run(["opa", "version"], capture_output=True, text=True, timeout=5)
        _opa_cache = r.returncode == 0
    except Exception:
        _opa_cache = False
    return _opa_cache


def _conftest_available() -> bool:
    """Check if conftest binary is on PATH (result cached)."""
    global _conftest_cache
    if _conftest_cache is not None:
        return _conftest_cache
    try:
        r = subprocess.run(["conftest", "--version"], capture_output=True, text=True, timeout=5)
        _conftest_cache = r.returncode == 0
    except Exception:
        _conftest_cache = False
    return _conftest_cache


def _trivy_available() -> bool:
    """Check if trivy binary is on PATH (result cached)."""
    global _trivy_cache
    if _trivy_cache is not None:
        return _trivy_cache
    try:
        r = subprocess.run(["trivy", "--version"], capture_output=True, text=True, timeout=5)
        _trivy_cache = r.returncode == 0
    except Exception:
        _trivy_cache = False
    return _trivy_cache


def validate_rego_file(rego_content: str) -> dict:
    """Basic sanitization and validation of user-uploaded Rego policy."""
    issues = []

    # Check for package declaration
    if "package " not in rego_content:
        issues.append("Missing 'package' declaration")

    # Check for dangerous operations (file I/O, HTTP, exec)
    dangerous = [
        (r"\bhttp\.send\b", "HTTP operations not allowed in policy"),
        (r"\bos\.exec\b", "OS exec not allowed in policy"),
        (r"\btrace\b", "Trace statements should be removed"),
    ]
    for pattern, msg in dangerous:
        if re.search(pattern, rego_content):
            issues.append(msg)

    # Basic syntax check
    if rego_content.count("{") != rego_content.count("}"):
        issues.append("Mismatched braces in policy")

    # Check it has deny rules (expected for compliance)
    if "deny[" not in rego_content and "deny " not in rego_content:
        issues.append("Warning: no 'deny' rules found — policy may not enforce anything")

    return {
        "valid": len([i for i in issues if not i.startswith("Warning")]) == 0,
        "issues": issues,
        "message": "Policy sanitization passed" if not issues else "; ".join(issues),
    }


def validate_with_opa(
    terraform_code: str,
    rego_policy: str,
    log_callback=None,
) -> dict:
    """Validate Terraform remediation code against Rego policy.

    Tries, in order: conftest → trivy → OPA eval → Python fallback.
    """
    if _conftest_available() and rego_policy:
        if log_callback:
            log_callback("Using conftest for Terraform policy validation")
        return _validate_conftest(terraform_code, rego_policy, log_callback)
    if _trivy_available():
        if log_callback:
            log_callback("Using trivy config for Terraform validation")
        return _validate_trivy(terraform_code, log_callback)
    if _opa_available() and rego_policy:
        if log_callback:
            log_callback("Using OPA eval for policy validation")
        return _validate_opa_real(terraform_code, rego_policy, log_callback)

    if log_callback:
        log_callback("No policy tool found (conftest/trivy/opa) — using Python fallback")
    return _validate_python_fallback(terraform_code, rego_policy)


# ─── conftest validation ──────────────────────────────────────────

def _validate_conftest(tf_code: str, rego_policy: str, log_cb=None) -> dict:
    """Run ``conftest test`` on a .tf file against the supplied Rego policy."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tf_path = os.path.join(tmpdir, "main.tf")
        policy_dir = os.path.join(tmpdir, "policy")
        os.makedirs(policy_dir, exist_ok=True)
        policy_path = os.path.join(policy_dir, "security_policy.rego")

        with open(tf_path, "w") as f:
            f.write(tf_code)
        with open(policy_path, "w") as f:
            f.write(rego_policy)

        try:
            cmd = [
                "conftest", "test", tf_path,
                "--policy", policy_dir,
                "--output", "json",
                "--no-color",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            violations = []
            try:
                output = json.loads(result.stdout)
                for entry in output:
                    for failure in entry.get("failures", []):
                        violations.append(failure.get("msg", str(failure)))
                    for warning in entry.get("warnings", []):
                        violations.append(f"WARNING: {warning.get('msg', str(warning))}")
            except (json.JSONDecodeError, TypeError):
                if result.returncode != 0 and result.stderr:
                    violations.append(result.stderr[:300])

            return {
                "method": "conftest",
                "compliant": len(violations) == 0,
                "violations": violations,
                "violation_count": len(violations),
                "message": (
                    "conftest: All policies passed"
                    if not violations
                    else f"conftest: {len(violations)} violations found"
                ),
            }
        except subprocess.TimeoutExpired:
            return {"method": "conftest", "compliant": False, "message": "conftest timed out"}
        except Exception as e:
            return {"method": "conftest", "compliant": False, "message": f"conftest error: {str(e)[:200]}"}


# ─── trivy config validation ─────────────────────────────────────

def _validate_trivy(tf_code: str, log_cb=None) -> dict:
    """Run ``trivy config`` on Terraform code for misconfiguration scanning."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tf_path = os.path.join(tmpdir, "main.tf")
        with open(tf_path, "w") as f:
            f.write(tf_code)

        try:
            cmd = [
                "trivy", "config", tmpdir,
                "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            violations = []
            try:
                output = json.loads(result.stdout)
                for res in output.get("Results", []):
                    for misconfig in res.get("Misconfigurations", []):
                        sev = misconfig.get("Severity", "")
                        title = misconfig.get("Title", "")
                        msg = misconfig.get("Message", "")
                        violations.append(f"{sev}: {title} — {msg}")
            except (json.JSONDecodeError, TypeError):
                if result.returncode != 0 and result.stderr:
                    violations.append(result.stderr[:300])

            return {
                "method": "trivy",
                "compliant": len(violations) == 0,
                "violations": violations,
                "violation_count": len(violations),
                "message": (
                    "trivy: No misconfigurations found"
                    if not violations
                    else f"trivy: {len(violations)} misconfigurations found"
                ),
            }
        except subprocess.TimeoutExpired:
            return {"method": "trivy", "compliant": False, "message": "trivy timed out"}
        except Exception as e:
            return {"method": "trivy", "compliant": False, "message": f"trivy error: {str(e)[:200]}"}


def _validate_opa_real(tf_code: str, rego_policy: str, log_cb) -> dict:
    """Run OPA eval with the given policy and Terraform code as input."""
    results = []

    with tempfile.TemporaryDirectory() as tmpdir:
        policy_path = os.path.join(tmpdir, "policy.rego")
        input_path = os.path.join(tmpdir, "input.json")

        with open(policy_path, "w") as f:
            f.write(rego_policy)

        # Convert TF code into a JSON input structure OPA can evaluate
        input_data = _terraform_to_opa_input(tf_code)
        with open(input_path, "w") as f:
            json.dump(input_data, f)

        try:
            cmd = [
                "opa", "eval",
                "--data", policy_path,
                "--input", input_path,
                "--format", "json",
                "data.terraform.grc.deny",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                output = json.loads(result.stdout)
                violations = []
                for r in output.get("result", []):
                    exprs = r.get("expressions", [])
                    for expr in exprs:
                        val = expr.get("value", [])
                        if isinstance(val, list):
                            violations.extend(val)
                        elif isinstance(val, set):
                            violations.extend(list(val))

                return {
                    "method": "opa",
                    "compliant": len(violations) == 0,
                    "violations": violations,
                    "violation_count": len(violations),
                    "message": "OPA: All policies passed" if not violations else f"OPA: {len(violations)} violations found",
                }
            else:
                return {
                    "method": "opa",
                    "compliant": False,
                    "violations": [result.stderr[:300]],
                    "message": f"OPA evaluation error: {result.stderr[:200]}",
                }
        except subprocess.TimeoutExpired:
            return {"method": "opa", "compliant": False, "message": "OPA evaluation timed out"}
        except Exception as e:
            return {"method": "opa", "compliant": False, "message": f"OPA error: {str(e)[:200]}"}


def _validate_python_fallback(tf_code: str, rego_policy: str) -> dict:
    """Python-based compliance check when OPA is not installed."""
    violations = []
    code_lower = tf_code.lower()

    # Check encryption
    if "aws_s3_bucket" in code_lower or "storage_account" in code_lower:
        if "encryption" not in code_lower and "sse_algorithm" not in code_lower and "enable_https" not in code_lower:
            violations.append("CRITICAL: Resource may be missing encryption configuration")

    if "aws_db_instance" in code_lower or "azurerm_mssql" in code_lower:
        if "storage_encrypted" not in code_lower and "true" not in code_lower:
            violations.append("CRITICAL: Database may not have storage encryption enabled")

    # Check public access
    if "publicly_accessible" in code_lower:
        if "true" in code_lower.split("publicly_accessible")[1][:20]:
            violations.append("HIGH: Resource is set to publicly accessible")

    if "block_public_acls" in code_lower and "false" in code_lower:
        violations.append("HIGH: S3 bucket public ACL blocking is disabled")

    # Check TLS version
    if "tls_version" in code_lower or "minimum_tls" in code_lower:
        if '"1.0"' in code_lower or '"1.1"' in code_lower:
            violations.append("MEDIUM: TLS version should be 1.2 or higher")

    # Check purge protection
    if "key_vault" in code_lower or "keyvault" in code_lower:
        if "purge_protection_enabled" in code_lower and "false" in code_lower:
            violations.append("HIGH: Key Vault purge protection should be enabled")

    # Check backup
    if "backup" in code_lower:
        if "enabled" in code_lower and "false" in code_lower.split("backup")[1][:50]:
            violations.append("MEDIUM: Backup should be enabled")

    # Check security group all traffic
    if "security_group" in code_lower:
        if "0.0.0.0/0" in tf_code:
            violations.append("CRITICAL: Security group allows traffic from 0.0.0.0/0")

    return {
        "method": "python-fallback",
        "compliant": len(violations) == 0,
        "violations": violations,
        "violation_count": len(violations),
        "message": (
            "Python check: All basic policies passed"
            if not violations
            else f"Python check: {len(violations)} potential issues found"
        ),
    }


def _terraform_to_opa_input(tf_code: str) -> dict:
    """Convert Terraform HCL code snippet into a simplified JSON input for OPA."""
    input_data = {"resource": {}}

    # Simple regex-based HCL parsing for common resource types
    resource_pattern = r'resource\s+"(\w+)"\s+"(\w+)"\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'
    matches = re.finditer(resource_pattern, tf_code, re.DOTALL)

    for match in matches:
        r_type = match.group(1)
        r_name = match.group(2)
        r_body = match.group(3)

        props = {}
        prop_pattern = r'(\w+)\s*=\s*("?[^"\n]+"?|true|false|\d+)'
        for prop_match in re.finditer(prop_pattern, r_body):
            key = prop_match.group(1)
            val = prop_match.group(2).strip('"')
            if val == "true":
                val = True
            elif val == "false":
                val = False
            elif val.isdigit():
                val = int(val)
            props[key] = val

        if r_type not in input_data["resource"]:
            input_data["resource"][r_type] = {}
        input_data["resource"][r_type][r_name] = props

    return input_data


def batch_validate_remediations(
    remediations: list[dict],
    rego_policy: str,
    tf_dir: str = "",
    log_callback=None,
) -> list[dict]:
    """Validate AI-generated Terraform remediation code against OPA Rego policy.

    If ``tf_dir`` is supplied and contains .tf files, runs
    ``conftest test <file>.tf -p <policy_dir>`` on each file directly.
    Otherwise falls back to extracting HCL from the analysis text.
    """
    # If conftest is available and we have real .tf files on disk, use them directly
    tf_files = []
    if tf_dir and os.path.isdir(tf_dir):
        tf_files = sorted(Path(tf_dir).glob("*.tf"))

    if tf_files and _conftest_available() and rego_policy:
        if log_callback:
            log_callback(f"Using conftest on {len(tf_files)} extracted .tf files")
        return _batch_conftest(tf_files, rego_policy, remediations, log_callback)

    # Fallback: per-finding validation from analysis text
    def _validate_one(idx_rem):
        i, rem = idx_rem
        analysis = rem.get("analysis", "")
        code_blocks = rem.get("terraform_blocks") or []
        if not code_blocks:
            hcl_pattern = r"```(?:hcl|terraform)?\s*(.*?)\s*```"
            code_blocks = re.findall(hcl_pattern, analysis, re.DOTALL)

        if not code_blocks:
            return i, {
                "finding": rem.get("finding_title", ""),
                "has_code": False,
                "validated": False,
                "message": "No Terraform code found in remediation",
            }

        combined_code = "\n\n".join(code_blocks)
        validation = validate_with_opa(combined_code, rego_policy, log_callback)

        return i, {
            "finding": rem.get("finding_title", ""),
            "has_code": True,
            "validated": True,
            "compliant": validation.get("compliant", False),
            "violations": validation.get("violations", []),
            "method": validation.get("method", ""),
            "message": validation.get("message", ""),
        }

    total = len(remediations)
    max_workers = min(4, total) if total > 1 else 1
    indexed_results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_validate_one, (i, rem)): i
            for i, rem in enumerate(remediations)
        }
        for future in as_completed(futures):
            idx, result = future.result()
            indexed_results[idx] = result

    return [indexed_results[i] for i in range(total)]


def _batch_conftest(
    tf_files: list,
    rego_policy: str,
    remediations: list[dict],
    log_cb=None,
) -> list[dict]:
    """Run ``conftest test <file>.tf --policy <policy_dir>`` on each .tf file."""
    results = []

    # Write rego policy to a temp dir once
    with tempfile.TemporaryDirectory() as policy_tmpdir:
        policy_dir = os.path.join(policy_tmpdir, "policy")
        os.makedirs(policy_dir, exist_ok=True)
        policy_path = os.path.join(policy_dir, "security_policy.rego")
        with open(policy_path, "w") as f:
            f.write(rego_policy)

        # Build a map: item index → list of .tf files for that item
        item_files = {}
        for tf_path in tf_files:
            # Filenames: item_0_block_0_resource.tf
            name = tf_path.stem
            parts = name.split("_")
            try:
                item_idx = int(parts[1]) if len(parts) > 1 else -1
            except (ValueError, IndexError):
                item_idx = -1
            item_files.setdefault(item_idx, []).append(tf_path)

        # Validate per remediation item
        for i, rem in enumerate(remediations):
            files = item_files.get(i, [])
            if not files:
                results.append({
                    "finding": rem.get("finding_title", ""),
                    "has_code": False,
                    "validated": False,
                    "message": "No Terraform .tf file found for this remediation",
                })
                continue

            all_violations = []
            for tf_path in files:
                try:
                    cmd = [
                        "conftest", "test", str(tf_path),
                        "--policy", policy_dir,
                        "--output", "json",
                        "--no-color",
                    ]
                    if log_cb:
                        log_cb(f"  conftest test {tf_path.name} -p policy/")
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                    try:
                        output = json.loads(result.stdout)
                        for entry in output:
                            for failure in entry.get("failures", []):
                                all_violations.append(failure.get("msg", str(failure)))
                            for warning in entry.get("warnings", []):
                                all_violations.append(f"WARNING: {warning.get('msg', str(warning))}")
                    except (json.JSONDecodeError, TypeError):
                        if result.returncode != 0 and result.stderr:
                            all_violations.append(result.stderr[:300])

                except subprocess.TimeoutExpired:
                    all_violations.append(f"conftest timed out on {tf_path.name}")
                except Exception as e:
                    all_violations.append(f"conftest error on {tf_path.name}: {str(e)[:200]}")

            results.append({
                "finding": rem.get("finding_title", ""),
                "has_code": True,
                "validated": True,
                "compliant": len(all_violations) == 0,
                "violations": all_violations,
                "violation_count": len(all_violations),
                "method": "conftest",
                "tf_files": [str(p.name) for p in files],
                "message": (
                    f"conftest: All policies passed ({len(files)} .tf files)"
                    if not all_violations
                    else f"conftest: {len(all_violations)} violations in {len(files)} .tf files"
                ),
            })

    return results
