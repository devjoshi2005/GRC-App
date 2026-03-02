"""FAIR (Factor Analysis of Information Risk) risk quantification engine.
Adapted from the GRC Compliance Engine reference implementation.
Uses IBM Data Breach Report 2025 metrics for financial impact calculations."""

import json
from datetime import datetime
from typing import Any

# ─── IBM Data Breach Report 2025 Metrics ─────────────────────────
IBM_METRICS = {
    "avg_breach_cost_usd": 4_880_000,
    "avg_cost_per_record": 165,
    "healthcare_multiplier": 2.24,
    "financial_multiplier": 1.25,
    "cloud_misconfig_pct": 0.12,
    "credential_pct": 0.16,
    "avg_detection_days": 194,
    "avg_containment_days": 64,
    "avg_lifecycle_days": 258,
}

THREAT_EVENT_FREQUENCY = {
    "Critical": 0.30,
    "High": 0.15,
    "Medium": 0.05,
    "Low": 0.01,
}

LOSS_MAGNITUDE = {
    "Highly Sensitive": 1_000_000,
    "Sensitive": 100_000,
    "Internal": 10_000,
    "Public": 1_000,
}

CONTROL_EFFECTIVENESS = {
    "mfa_enabled": 0.90,
    "encryption_enabled": 0.95,
    "security_group_restricted": 0.80,
    "iam_policy_least_privilege": 0.85,
    "backup_enabled": 0.70,
    "logging_enabled": 0.60,
    "root_account_restricted": 0.95,
    "default": 0.0,
}

FINDING_CONTROL_MAP = {
    "iam_administrator_access_with_mfa": 0.0,
    "iam_aws_attached_policy_no_administrative_privileges": 0.0,
    "iam_no_root_access_key": 0.0,
    "iam_avoid_root_usage": 0.0,
    "iam_root_hardware_mfa_enabled": 0.90,
    "iam_policy_allows_privilege_escalation": 0.0,
    "ec2_securitygroup_allow_ingress_from_internet_to_all_ports": 0.0,
    "ec2_instance_port_ssh_exposed_to_internet": 0.0,
    "ec2_instance_port_rdp_exposed_to_internet": 0.0,
    "ec2_instance_port_telnet_exposed_to_internet": 0.0,
    "s3_bucket_server_side_encryption": 0.0,
    "s3_bucket_public_access": 0.0,
    "cloudtrail_multi_region_enabled": 0.60,
    "rds_instance_storage_encrypted": 0.0,
    "rds_instance_publicly_accessible": 0.0,
    "storage_account_https_only": 0.0,
    "sql_server_minimum_tls_version": 0.0,
    "keyvault_purge_protection_enabled": 0.0,
    "network_nsg_rdp_restricted": 0.0,
    "defender_for_servers_enabled": 0.0,
}


def get_resource_context(finding: dict) -> dict:
    """Extract resource classification and context from Prowler finding."""
    resources = finding.get("resources", [{}])
    resource = resources[0] if resources else {}
    uid = resource.get("uid", "").lower()
    name = resource.get("name", "").lower()

    context = {
        "class": "Internal",
        "is_public": False,
        "is_active": True,
        "soft_delete": True,
        "retention": 30,
        "service": "unknown",
    }

    # Service classification
    if any(x in uid for x in ["iam", "role", "user", "group", "admin", "service_principal"]):
        context["service"] = "IAM"
        context["class"] = "Sensitive"
    elif any(x in uid for x in ["s3", "storage", "bucket", "blob"]):
        context["service"] = "Storage"
        context["class"] = "Highly Sensitive"
    elif any(x in uid for x in ["rds", "sql", "database", "dynamodb", "cosmos"]):
        context["service"] = "Database"
        context["class"] = "Highly Sensitive"
    elif any(x in uid for x in ["ec2", "vm", "instance", "compute"]):
        context["service"] = "Compute"
        context["class"] = "Sensitive"
    elif any(x in uid for x in ["lambda", "function"]):
        context["service"] = "Lambda"
        context["class"] = "Internal"
    elif any(x in uid for x in ["kms", "key", "vault", "secret"]):
        context["service"] = "KeyManagement"
        context["class"] = "Highly Sensitive"
    elif any(x in uid for x in ["cloudtrail", "log", "monitor", "insight"]):
        context["service"] = "Logging"
        context["class"] = "Sensitive"
    elif any(x in uid for x in ["security_group", "sg-", "nsg", "vpc", "network", "firewall"]):
        context["service"] = "Networking"
        context["class"] = "Sensitive"
    elif any(x in uid for x in ["guardduty", "defender", "security"]):
        context["service"] = "Security"
        context["class"] = "Sensitive"
    elif any(x in uid for x in ["ebs", "disk", "volume"]):
        context["service"] = "Storage"
        context["class"] = "Sensitive"

    # Check for public exposure
    title = finding.get("finding_info", {}).get("title", "").lower()
    event_code = finding.get("metadata", {}).get("event_code", "").lower()
    if any(x in title + event_code for x in ["public", "internet", "exposed", "0.0.0.0"]):
        context["is_public"] = True

    # Check unmapped categories
    unmapped = finding.get("unmapped", {})
    categories = unmapped.get("categories", []) if isinstance(unmapped, dict) else []
    if "internet-exposed" in categories:
        context["is_public"] = True

    return context


def calculate_control_effectiveness(finding: dict) -> float:
    """Map Prowler finding to control effectiveness score."""
    event_code = finding.get("metadata", {}).get("event_code", "")

    if event_code in FINDING_CONTROL_MAP:
        return FINDING_CONTROL_MAP[event_code]

    ec_lower = event_code.lower()

    if "mfa" in ec_lower:
        return 0.0 if finding.get("status_code") == "FAIL" else CONTROL_EFFECTIVENESS["mfa_enabled"]
    if "encryption" in ec_lower or "kms" in ec_lower or "encrypt" in ec_lower:
        return 0.0 if finding.get("status_code") == "FAIL" else CONTROL_EFFECTIVENESS["encryption_enabled"]
    if "securitygroup" in ec_lower or "nsg" in ec_lower:
        return 0.0 if "all_ports" in ec_lower else CONTROL_EFFECTIVENESS["security_group_restricted"]
    if "iam" in ec_lower and "privilege" in ec_lower:
        return 0.0
    if "backup" in ec_lower:
        return CONTROL_EFFECTIVENESS["backup_enabled"]
    if "logging" in ec_lower or "trail" in ec_lower or "monitor" in ec_lower:
        return CONTROL_EFFECTIVENESS["logging_enabled"]

    severity = finding.get("severity", "High")
    return {"Critical": 0.0, "High": 0.10, "Medium": 0.30, "Low": 0.50}.get(severity, 0.0)


def calculate_ale(loss_magnitude: float, threat_frequency: float, control_effectiveness: float) -> float:
    """
    Calculate Annualized Loss Expectancy using FAIR model.
    ALE = Loss_Magnitude × Threat_Event_Frequency × (1 - Control_Effectiveness) × 365
    """
    residual_risk = 1.0 - min(max(control_effectiveness, 0.0), 1.0)
    ale = loss_magnitude * threat_frequency * residual_risk * 365
    return round(ale, 2)


def generate_risk_report(
    findings: list[dict],
    log_callback=None,
) -> dict:
    """
    Generate FAIR-based risk quantification report from Prowler findings.
    Returns structured risk data with per-finding ALE and summary statistics.
    """
    risk_records = []

    for idx, finding in enumerate(findings):
        try:
            resources = finding.get("resources", [])
            if not resources:
                continue

            resource = resources[0]
            r_uid = resource.get("uid", "unknown")
            r_name = resource.get("name", r_uid.split("/")[-1] if "/" in r_uid else r_uid)
            r_type = resource.get("type", "")

            context = get_resource_context(finding)
            severity = finding.get("severity", "High")

            threat_frequency = THREAT_EVENT_FREQUENCY.get(severity, 0.15)
            loss_magnitude = LOSS_MAGNITUDE.get(context["class"], 10_000)
            control_effectiveness = calculate_control_effectiveness(finding)

            ale = calculate_ale(loss_magnitude, threat_frequency, control_effectiveness)

            # Extract compliance mapping
            unmapped = finding.get("unmapped", {})
            compliance = unmapped.get("compliance", {}) if isinstance(unmapped, dict) else {}
            frameworks = list(compliance.keys()) if isinstance(compliance, dict) else []

            nist_controls = []
            if isinstance(compliance, dict):
                nist_controls = (
                    compliance.get("NIST-800-53-Revision-5", []) or
                    compliance.get("NIST-CSF-2.0", []) or
                    compliance.get("NIST-800-53-Revision-4", []) or []
                )

            primary_control = nist_controls[0] if nist_controls else "SC-7"

            record = {
                "asset": r_name,
                "asset_uid": r_uid,
                "asset_type": r_type,
                "service": context["service"],
                "severity": severity,
                "classification": context["class"],
                "is_public": context["is_public"],
                "is_active": context["is_active"],
                "retention_days": context["retention"],
                "soft_delete": context["soft_delete"],
                "threat_frequency": threat_frequency,
                "loss_magnitude": loss_magnitude,
                "control_effectiveness": round(control_effectiveness, 2),
                "ale": ale,
                "control": primary_control,
                "compliance": ", ".join(frameworks[:5]),
                "finding_code": finding.get("metadata", {}).get("event_code", ""),
                "finding_title": finding.get("finding_info", {}).get("title", ""),
                "risk_details": finding.get("risk_details", "")[:200],
                "remediation": finding.get("remediation", {}).get("desc", "")[:200],
                "region": resource.get("region", "unknown"),
                "cloud_provider": finding.get("cloud", {}).get("provider", "aws"),
                "account_id": finding.get("cloud", {}).get("account", {}).get("uid", "unknown"),
                "status": finding.get("status_code", "FAIL"),
                "created_time": finding.get("finding_info", {}).get("created_time_dt", ""),
            }

            risk_records.append(record)

        except Exception as e:
            if log_callback:
                log_callback(f"Skipping finding {idx}: {str(e)[:80]}")
            continue

    # Calculate summary statistics
    total_ale = sum(r["ale"] for r in risk_records)
    avg_ale = total_ale / len(risk_records) if risk_records else 0

    severity_counts = {}
    for s in ["Critical", "High", "Medium", "Low"]:
        severity_counts[s] = len([r for r in risk_records if r["severity"] == s])

    class_counts = {}
    for c in ["Highly Sensitive", "Sensitive", "Internal", "Public"]:
        class_counts[c] = len([r for r in risk_records if r["classification"] == c])

    service_counts = {}
    for r in risk_records:
        svc = r["service"]
        service_counts[svc] = service_counts.get(svc, 0) + 1

    summary = {
        "total_findings": len(risk_records),
        "total_ale": round(total_ale, 2),
        "avg_ale": round(avg_ale, 2),
        "max_ale": round(max((r["ale"] for r in risk_records), default=0), 2),
        "severity_distribution": severity_counts,
        "classification_distribution": class_counts,
        "service_distribution": service_counts,
        "ibm_context": {
            "avg_breach_cost": IBM_METRICS["avg_breach_cost_usd"],
            "cost_per_record": IBM_METRICS["avg_cost_per_record"],
            "avg_detection_days": IBM_METRICS["avg_detection_days"],
            "total_ale_as_pct_of_avg_breach": round(
                (total_ale / IBM_METRICS["avg_breach_cost_usd"]) * 100, 2
            ) if total_ale else 0,
        },
        "methodology": "FAIR (Factor Analysis of Information Risk)",
        "generated_at": datetime.now().isoformat(),
    }

    if log_callback:
        log_callback(f"Risk quantification complete: {len(risk_records)} findings, Total ALE: ${total_ale:,.2f}")

    return {
        "success": True,
        "records": risk_records,
        "summary": summary,
        "message": f"Quantified {len(risk_records)} findings — Total ALE: ${total_ale:,.2f}",
    }
