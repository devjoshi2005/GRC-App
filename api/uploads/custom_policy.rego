package terraform.grc

import future.keywords.if
import future.keywords.in

default allow = false

deny[msg] {
    resource := input.resource.aws_s3_bucket_server_side_encryption_configuration[_]
    rule := resource.rule[_]
    not rule.apply_server_side_encryption_by_default.sse_algorithm
    msg := sprintf("CRITICAL: S3 Bucket encryption missing for resource '%v'", [resource.bucket])
}

deny[msg] {
    resource := input.resource.aws_s3_bucket_public_access_block[_]
    not resource.block_public_acls == true
    not resource.block_public_policy == true
    msg := sprintf("HIGH: S3 Bucket '%v' allows public ACLs or Policies", [resource.bucket])
}

deny[msg] {
    resource := input.resource.aws_db_instance[_]
    not resource.storage_encrypted == true
    msg := sprintf("CRITICAL: AWS RDS Instance '%v' is not encrypted", [resource.allocated_storage])
}

deny[msg] {
    resource := input.resource.aws_db_instance[_]
    resource.publicly_accessible == true
    msg := sprintf("CRITICAL: AWS RDS Instance is set to 'publicly_accessible = true'. This violates CIS Benchmarks.", [])
}

deny[msg] {
    resource := input.resource.azurerm_mssql_server[_]
    resource.minimum_tls_version != "1.2"
    msg := sprintf("MEDIUM: Azure SQL Server '%v' is using an old TLS version", [resource.name])
}

deny[msg] {
    resource := input.resource.azurerm_storage_account[_]
    # In Azure provider, 'enable_https_traffic_only' defaults to true, but good to check if explicitly disabled
    resource.enable_https_traffic_only == false
    msg := sprintf("HIGH: Azure Storage Account '%v' allows HTTP traffic", [resource.name])
}

deny[msg] {
    resource := input.resource.azurerm_key_vault[_]
    resource.purge_protection_enabled == false
    msg := sprintf("HIGH: Azure Key Vault '%v' has Purge Protection DISABLED. Secrets can be permanently deleted by attackers.", [resource.name])
}


# Rule: DataSync Logs must go to CloudWatch
deny[msg] {
    resource := input.resource.aws_datasync_task[_]
    not resource.cloudwatch_log_group_arn
    msg := sprintf("MEDIUM: AWS DataSync Task '%v' does not have CloudWatch logging enabled", [resource.name])
}

# Only return 'true' if there are zero violations
allow {
    count(deny) == 0
}