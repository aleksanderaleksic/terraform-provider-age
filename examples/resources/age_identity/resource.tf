resource "age_identity" "backup" {}

# Rotate by bumping the keeper (or with `tofu apply -replace=age_identity.backup`).
resource "age_identity" "rotating" {
  keepers = {
    rotation = "1"
  }
}

output "backup_recipient" {
  value = age_identity.backup.recipient
}
