"""OPA Rego policy validation engine.
Uses OPA binary when available; falls back to Python-based validation."""

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


def _opa_available() -> bool:
    try:
        r = subprocess.run(["opa", "version"], capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


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
    """Validate Terraform remediation code against OPA Rego policy."""

    if _opa_available():
        return _validate_opa_real(terraform_code, rego_policy, log_callback)
    else:
        if log_callback:
            log_callback("OPA binary not found — using Python regex policy check")
        return _validate_python_fallback(terraform_code, rego_policy)


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
    log_callback=None,
) -> list[dict]:
    """Validate all AI-generated remediation code against OPA policy."""
    results = []

    for i, rem in enumerate(remediations):
        analysis = rem.get("analysis", "")

        # Extract HCL/Terraform code blocks
        hcl_pattern = r"```(?:hcl|terraform)?\s*(.*?)\s*```"
        code_blocks = re.findall(hcl_pattern, analysis, re.DOTALL)

        if not code_blocks:
            results.append({
                "finding": rem.get("finding_title", ""),
                "has_code": False,
                "validated": False,
                "message": "No Terraform code found in remediation",
            })
            continue

        combined_code = "\n\n".join(code_blocks)
        validation = validate_with_opa(combined_code, rego_policy, log_callback)

        results.append({
            "finding": rem.get("finding_title", ""),
            "has_code": True,
            "validated": True,
            "compliant": validation.get("compliant", False),
            "violations": validation.get("violations", []),
            "method": validation.get("method", ""),
            "message": validation.get("message", ""),
        })

        if log_callback:
            status = "PASS" if validation.get("compliant") else "FAIL"
            log_callback(f"  [{i+1}] OPA {status}: {rem.get('finding_title', '')[:50]}...")

    return results
