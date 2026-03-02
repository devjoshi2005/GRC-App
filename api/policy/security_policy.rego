package terraform.grc

import future.keywords.if
import future.keywords.in

default allow = false

# ─── S3 / Storage Encryption ─────────────────────────────────
deny[msg] {
    resource := input.resource.aws_s3_bucket_server_side_encryption_configuration[_]
    rule := resource.rule[_]
    not rule.apply_server_side_encryption_by_default.sse_algorithm
    msg := sprintf("CRITICAL: S3 Bucket encryption missing for resource '%v'", [resource.bucket])
}

# ─── S3 Public Access ────────────────────────────────────────
deny[msg] {
    resource := input.resource.aws_s3_bucket_public_access_block[_]
    not resource.block_public_acls == true
    not resource.block_public_policy == true
    msg := sprintf("HIGH: S3 Bucket '%v' allows public ACLs or Policies", [resource.bucket])
}

# ─── RDS Encryption ──────────────────────────────────────────
deny[msg] {
    resource := input.resource.aws_db_instance[_]
    not resource.storage_encrypted == true
    msg := sprintf("CRITICAL: AWS RDS Instance '%v' is not encrypted", [resource.allocated_storage])
}

# ─── RDS Public Access ───────────────────────────────────────
deny[msg] {
    resource := input.resource.aws_db_instance[_]
    resource.publicly_accessible == true
    msg := sprintf("CRITICAL: AWS RDS Instance is set to 'publicly_accessible = true'. This violates CIS Benchmarks.", [])
}

# ─── Azure SQL TLS Version ───────────────────────────────────
deny[msg] {
    resource := input.resource.azurerm_mssql_server[_]
    resource.minimum_tls_version != "1.2"
    msg := sprintf("MEDIUM: Azure SQL Server '%v' is using an old TLS version", [resource.name])
}

# ─── Azure Storage HTTPS ─────────────────────────────────────
deny[msg] {
    resource := input.resource.azurerm_storage_account[_]
    resource.enable_https_traffic_only == false
    msg := sprintf("HIGH: Azure Storage Account '%v' allows HTTP traffic", [resource.name])
}

# ─── Azure Key Vault Purge Protection ────────────────────────
deny[msg] {
    resource := input.resource.azurerm_key_vault[_]
    resource.purge_protection_enabled == false
    msg := sprintf("HIGH: Azure Key Vault '%v' has Purge Protection DISABLED. Secrets can be permanently deleted by attackers.", [resource.name])
}

# ─── AWS DataSync Logging ────────────────────────────────────
deny[msg] {
    resource := input.resource.aws_datasync_task[_]
    not resource.cloudwatch_log_group_arn
    msg := sprintf("MEDIUM: AWS DataSync Task '%v' does not have CloudWatch logging enabled", [resource.name])
}

# ─── Security Group Open to World ────────────────────────────
deny[msg] {
    resource := input.resource.aws_security_group_rule[_]
    resource.type == "ingress"
    resource.cidr_blocks[_] == "0.0.0.0/0"
    msg := sprintf("CRITICAL: Security group rule allows ingress from 0.0.0.0/0 on port %v", [resource.from_port])
}

# ─── EBS Volume Encryption ───────────────────────────────────
deny[msg] {
    resource := input.resource.aws_ebs_volume[_]
    not resource.encrypted == true
    msg := sprintf("HIGH: EBS volume '%v' is not encrypted", [resource.availability_zone])
}

# ─── Azure NSG Open RDP ──────────────────────────────────────
deny[msg] {
    resource := input.resource.azurerm_network_security_rule[_]
    resource.direction == "Inbound"
    resource.destination_port_range == "3389"
    resource.source_address_prefix == "*"
    msg := sprintf("CRITICAL: NSG rule '%v' allows RDP from any source", [resource.name])
}

# ─── Allow if no violations ──────────────────────────────────
allow {
    count(deny) == 0
}
