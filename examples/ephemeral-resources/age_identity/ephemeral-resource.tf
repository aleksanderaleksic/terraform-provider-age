# Generate a post-quantum identity and write it straight to 1Password, without
# it ever reaching state or plan. A new identity is generated on every run, but
# password_wo is only sent when password_wo_version changes, so the one in
# 1Password stays put. Bump the version to rotate.
ephemeral "age_identity" "backup" {
  post_quantum = true
}

resource "onepassword_item" "backup_identity" {
  vault    = var.vault_id
  title    = "backup-age-identity"
  category = "password"

  password_wo         = ephemeral.age_identity.backup.identity
  password_wo_version = 1
}
