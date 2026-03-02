"""Configuration constants for GRC Compliance Engine"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
POLICY_DIR = BASE_DIR / "policy"
OUTPUT_DIR = BASE_DIR / "outputs"
UPLOAD_DIR = BASE_DIR / "uploads"

# Ensure directories exist
OUTPUT_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

# Compliance frameworks (25+)
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
