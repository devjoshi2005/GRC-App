"""Configuration constants for GRC Compliance Engine"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
POLICY_DIR = BASE_DIR / "policy"

# On Vercel (read-only FS) write to /tmp; locally use api/outputs and api/uploads
_VERCEL = os.environ.get("VERCEL", "")
if _VERCEL:
    OUTPUT_DIR = Path("/tmp/grc_outputs")
    UPLOAD_DIR = Path("/tmp/grc_uploads")
else:
    OUTPUT_DIR = BASE_DIR / "outputs"
    UPLOAD_DIR = BASE_DIR / "uploads"

# Ensure writable directories exist
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Legacy combined frameworks dict (kept for backward compat with embeddings/report)
COMPLIANCE_FRAMEWORKS = {
    "pci_dss": {"name": "PCI-DSS v4.0.1", "category": "Financial"},
    "hipaa": {"name": "HIPAA", "category": "Healthcare"},
    "cis_aws": {"name": "CIS AWS Foundations v3.0", "category": "Cloud"},
    "cis_azure": {"name": "CIS Azure Foundations v2.0", "category": "Cloud"},
    "nist_800_53": {"name": "NIST SP 800-53 Rev 5", "category": "Government"},
    "nist_csf": {"name": "NIST CSF 2.0", "category": "Framework"},
    "iso_27001": {"name": "ISO 27001:2022", "category": "International"},
    "soc2": {"name": "SOC 2 Type II", "category": "Audit"},
    "gdpr": {"name": "GDPR", "category": "Privacy"},
    "sox": {"name": "SOX (Sarbanes-Oxley)", "category": "Financial"},
    "fisma": {"name": "FISMA", "category": "Government"},
    "fedramp": {"name": "FedRAMP", "category": "Government"},
    "ccpa": {"name": "CCPA/CPRA", "category": "Privacy"},
    "aws_waf": {"name": "AWS Well-Architected Security", "category": "Cloud"},
    "azure_security": {"name": "Azure Security Benchmark v3", "category": "Cloud"},
    "nist_800_171": {"name": "NIST 800-171 Rev 2", "category": "Defense"},
    "csa_ccm": {"name": "CSA CCM v4.0", "category": "Cloud"},
    "cis_docker": {"name": "CIS Docker Benchmark", "category": "Container"},
    "cis_kubernetes": {"name": "CIS Kubernetes Benchmark", "category": "Container"},
    "mitre_attack": {"name": "MITRE ATT&CK v14", "category": "Threat Intel"},
    "ens": {"name": "ENS (Spain National)", "category": "Regional"},
    "glba": {"name": "GLBA", "category": "Financial"},
    "ferpa": {"name": "FERPA", "category": "Education"},
    "cmmc": {"name": "CMMC v2.0", "category": "Defense"},
    "nist_iso_mapping": {"name": "NIST-ISO Mapping", "category": "Framework"},
    "cis_gcp": {"name": "CIS GCP Foundations v2.0", "category": "Cloud"},
}

# ─── Prowler-native compliance frameworks (actual --compliance values) ────
# These are the real IDs accepted by `prowler aws --compliance` / `prowler azure --compliance`.
# The key is the exact prowler framework ID; the value has a friendly display name + category.

AWS_COMPLIANCE_FRAMEWORKS = {
    "cis_5.0_aws":                                    {"name": "CIS AWS v5.0",                        "category": "CIS Benchmark"},
    "cis_4.0_aws":                                    {"name": "CIS AWS v4.0",                        "category": "CIS Benchmark"},
    "cis_3.0_aws":                                    {"name": "CIS AWS v3.0",                        "category": "CIS Benchmark"},
    "cis_2.0_aws":                                    {"name": "CIS AWS v2.0",                        "category": "CIS Benchmark"},
    "cis_1.5_aws":                                    {"name": "CIS AWS v1.5",                        "category": "CIS Benchmark"},
    "cis_1.4_aws":                                    {"name": "CIS AWS v1.4",                        "category": "CIS Benchmark"},
    "pci_4.0_aws":                                    {"name": "PCI-DSS v4.0",                        "category": "Financial"},
    "pci_3.2.1_aws":                                  {"name": "PCI-DSS v3.2.1",                      "category": "Financial"},
    "hipaa_aws":                                      {"name": "HIPAA",                                "category": "Healthcare"},
    "nist_800_53_revision_5_aws":                     {"name": "NIST 800-53 Rev 5",                   "category": "Government"},
    "nist_800_53_revision_4_aws":                     {"name": "NIST 800-53 Rev 4",                   "category": "Government"},
    "nist_800_171_revision_2_aws":                    {"name": "NIST 800-171 Rev 2",                  "category": "Defense"},
    "nist_csf_2.0_aws":                               {"name": "NIST CSF 2.0",                        "category": "Framework"},
    "nist_csf_1.1_aws":                               {"name": "NIST CSF 1.1",                        "category": "Framework"},
    "iso27001_2022_aws":                              {"name": "ISO 27001:2022",                      "category": "International"},
    "iso27001_2013_aws":                              {"name": "ISO 27001:2013",                      "category": "International"},
    "soc2_aws":                                       {"name": "SOC 2",                                "category": "Audit"},
    "gdpr_aws":                                       {"name": "GDPR",                                 "category": "Privacy"},
    "fedramp_moderate_revision_4_aws":                {"name": "FedRAMP Moderate Rev 4",              "category": "Government"},
    "fedramp_low_revision_4_aws":                     {"name": "FedRAMP Low Rev 4",                   "category": "Government"},
    "fedramp_20x_ksi_low_aws":                        {"name": "FedRAMP 20x KSI Low",                 "category": "Government"},
    "aws_foundational_security_best_practices_aws":   {"name": "AWS Foundational Security BP",        "category": "Cloud"},
    "aws_foundational_technical_review_aws":          {"name": "AWS Foundational Technical Review",   "category": "Cloud"},
    "aws_well_architected_framework_security_pillar_aws": {"name": "AWS Well-Arch Security Pillar",   "category": "Cloud"},
    "aws_well_architected_framework_reliability_pillar_aws": {"name": "AWS Well-Arch Reliability",    "category": "Cloud"},
    "aws_account_security_onboarding_aws":            {"name": "AWS Account Security Onboarding",     "category": "Cloud"},
    "aws_audit_manager_control_tower_guardrails_aws": {"name": "AWS Audit Manager / Control Tower",   "category": "Cloud"},
    "mitre_attack_aws":                               {"name": "MITRE ATT&CK",                        "category": "Threat Intel"},
    "cisa_aws":                                       {"name": "CISA",                                 "category": "Government"},
    "ens_rd2022_aws":                                 {"name": "ENS RD2022 (Spain)",                  "category": "Regional"},
    "nis2_aws":                                       {"name": "NIS2 Directive",                       "category": "EU Regulation"},
    "ffiec_aws":                                      {"name": "FFIEC",                                "category": "Financial"},
    "rbi_cyber_security_framework_aws":               {"name": "RBI Cyber Security (India)",           "category": "Regional"},
    "kisa_isms_p_2023_aws":                           {"name": "KISA ISMS-P 2023",                    "category": "Regional"},
    "kisa_isms_p_2023_korean_aws":                    {"name": "KISA ISMS-P 2023 (Korean)",           "category": "Regional"},
    "ccc_aws":                                        {"name": "CCC",                                  "category": "Framework"},
    "c5_aws":                                         {"name": "C5 (Germany BSI)",                    "category": "Regional"},
    "gxp_eu_annex_11_aws":                            {"name": "GxP EU Annex 11",                     "category": "Pharma"},
    "gxp_21_cfr_part_11_aws":                         {"name": "GxP 21 CFR Part 11",                  "category": "Pharma"},
    "prowler_threatscore_aws":                        {"name": "Prowler ThreatScore",                  "category": "Scoring"},
}

AZURE_COMPLIANCE_FRAMEWORKS = {
    "cis_5.0_azure":                                  {"name": "CIS Azure v5.0",                      "category": "CIS Benchmark"},
    "cis_4.0_azure":                                  {"name": "CIS Azure v4.0",                      "category": "CIS Benchmark"},
    "cis_3.0_azure":                                  {"name": "CIS Azure v3.0",                      "category": "CIS Benchmark"},
    "cis_2.1_azure":                                  {"name": "CIS Azure v2.1",                      "category": "CIS Benchmark"},
    "cis_2.0_azure":                                  {"name": "CIS Azure v2.0",                      "category": "CIS Benchmark"},
    "pci_4.0_azure":                                  {"name": "PCI-DSS v4.0",                        "category": "Financial"},
    "hipaa_azure":                                    {"name": "HIPAA",                                "category": "Healthcare"},
    "iso27001_2022_azure":                            {"name": "ISO 27001:2022",                      "category": "International"},
    "soc2_azure":                                     {"name": "SOC 2",                                "category": "Audit"},
    "fedramp_20x_ksi_low_azure":                      {"name": "FedRAMP 20x KSI Low",                 "category": "Government"},
    "mitre_attack_azure":                             {"name": "MITRE ATT&CK",                        "category": "Threat Intel"},
    "ens_rd2022_azure":                               {"name": "ENS RD2022 (Spain)",                  "category": "Regional"},
    "nis2_azure":                                     {"name": "NIS2 Directive",                       "category": "EU Regulation"},
    "rbi_cyber_security_framework_azure":             {"name": "RBI Cyber Security (India)",           "category": "Regional"},
    "ccc_azure":                                      {"name": "CCC",                                  "category": "Framework"},
    "c5_azure":                                       {"name": "C5 (Germany BSI)",                    "category": "Regional"},
    "prowler_threatscore_azure":                      {"name": "Prowler ThreatScore",                  "category": "Scoring"},
}

# OpenAI models
OPENAI_MODELS = ["gpt-4o", "gpt-5", "gpt-4o-mini", "gpt-4-turbo"]

# ─── Cloud Services (common ones for the UI selector — full list is
#     discovered dynamically at scan time via prowler --list-services) ───
AWS_SERVICES = [
    "accessanalyzer", "account", "acm", "apigateway", "athena", "autoscaling",
    "awslambda", "backup", "cloudformation", "cloudfront", "cloudtrail",
    "cloudwatch", "codeartifact", "codebuild", "cognito", "config",
    "directoryservice", "dlm", "dms", "documentdb", "dynamodb", "ec2",
    "ecr", "ecs", "efs", "eks", "elasticache", "elb", "elbv2", "emr",
    "fms", "glacier", "glue", "guardduty", "iam", "inspector2",
    "kinesis", "kms", "macie", "mq", "neptune", "networkfirewall",
    "opensearch", "organizations", "rds", "redshift", "resourceexplorer2",
    "route53", "s3", "sagemaker", "secretsmanager", "securityhub", "shield",
    "sns", "sqs", "ssm", "ssmincidents", "trustedadvisor", "vpc", "waf",
    "wafv2", "wellarchitected", "workspaces",
]

AZURE_SERVICES = [
    "aisearch", "app", "appinsights", "appservice", "cosmosdb", "defender",
    "entra", "iam", "keyvault", "monitor", "mysql", "network",
    "postgresql", "sqlserver", "storage",
]

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "informational"]

# ─── RISK ENGINE CONSTANTS (IBM Data Breach Report 2025) ───
IBM_DBR_2025 = {
    "avg_breach_cost": 4_880_000,
    "healthcare_avg": 10_930_000,
    "financial_avg": 6_080_000,
    "cloud_misconfiguration_pct": 0.12,
    "credential_compromise_pct": 0.16,
    "avg_detection_days": 194,
    "avg_containment_days": 64,
    "cost_per_record": 165,
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

# Prowler check → control effectiveness mapping
FINDING_CONTROL_MAP = {
    "iam_administrator_access_with_mfa": 0.0,
    "iam_aws_attached_policy_no_administrative_privileges": 0.0,
    "iam_no_root_access_key": 0.0,
    "iam_avoid_root_usage": 0.0,
    "iam_root_hardware_mfa_enabled": 0.90,
    "ec2_securitygroup_allow_ingress_from_internet_to_all_ports": 0.0,
    "ec2_instance_port_ssh_exposed_to_internet": 0.0,
    "ec2_instance_port_rdp_exposed_to_internet": 0.0,
    "ec2_instance_port_telnet_exposed_to_internet": 0.0,
    "s3_bucket_public_access": 0.0,
    "s3_bucket_server_side_encryption": 0.0,
    "cloudtrail_multi_region_enabled": 0.60,
    "rds_instance_storage_encrypted": 0.0,
    "rds_instance_publicly_accessible": 0.0,
}

# Default steampipe columns
DEFAULT_STEAMPIPE_COLUMNS = [
    "name", "tags", "publicly_accessible", "region",
    "encryption_status", "arn", "status", "instance_type"
]

# Severity filter for analysis
SEVERITY_FILTER = ["Critical", "High"]
