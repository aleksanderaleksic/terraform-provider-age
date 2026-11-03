# Wrap a random data-encryption key with a post-quantum identity, the way Klio
# (CloudNativePG backups) expects its encryption key file, and store both in
# 1Password. Neither the key, the identity nor the ciphertext reaches state.
#
# The identity and the ciphertext come from the same run, so they always match.
# Both write-only versions must change together: bumping only one stores an
# identity that can't open the stored ciphertext.
ephemeral "random_bytes" "data_key" {
  length = 32
}

ephemeral "age_identity" "backup" {
  post_quantum = true
}

ephemeral "age_encrypted" "data_key" {
  plaintext  = ephemeral.random_bytes.data_key.hex
  recipients = [ephemeral.age_identity.backup.recipient]
}

locals {
  # Bumping this generates a new data key: everything encrypted with the old
  # one becomes unreadable.
  key_version = 1
}

# The password category keeps both the password and the note; secure_note
# drops the password.
resource "onepassword_item" "klio_encryption" {
  vault    = var.vault_id
  title    = "klio-encryption"
  category = "password"

  password_wo           = ephemeral.age_identity.backup.identity
  password_wo_version   = local.key_version
  note_value_wo         = ephemeral.age_encrypted.data_key.ciphertext
  note_value_wo_version = local.key_version
}
