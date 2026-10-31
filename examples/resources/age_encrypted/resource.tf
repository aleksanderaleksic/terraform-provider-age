# Wrap a random data-encryption key with an age identity, the way tools such
# as Klio (CloudNativePG backups) expect their encryption key file.
resource "random_bytes" "data_key" {
  length = 32

  # Every ciphertext ever produced with this key needs it to decrypt.
  lifecycle {
    prevent_destroy = true
  }
}

resource "age_identity" "backup" {}

resource "age_encrypted" "data_key" {
  plaintext  = random_bytes.data_key.hex
  recipients = [age_identity.backup.recipient]
}

# Rotating the identity (`tofu apply -replace=age_identity.backup`) re-encrypts
# the same data key to the new recipient; the data key itself never changes.
output "encrypted_data_key" {
  value = age_encrypted.data_key.ciphertext
}
