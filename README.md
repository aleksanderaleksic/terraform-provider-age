# terraform-provider-age

An OpenTofu / Terraform provider for [age](https://age-encryption.org): generate
X25519 and post-quantum identities and encrypt data to age recipients, entirely
as code.

It exists to bootstrap keys that tools expect as age files, such as the
encryption key of [Klio](https://cloudnative-pg.io/klio/) (CloudNativePG
backups), without a one-off `age-keygen` script, and to rotate them with a
plain `apply`.

## Resources

| Resource | What it does |
|---|---|
| [`age_identity`](docs/resources/identity.md) | Generates an identity (`AGE-SECRET-KEY-1...`) and its recipient (`age1...`). Stable across plans; rotate with `-replace` or `keepers`. |
| [`age_encrypted`](docs/resources/encrypted.md) | Encrypts `plaintext` to one or more recipients, X25519 or post-quantum. Outputs ASCII-armored and single-line base64 ciphertext. Only re-encrypts when its inputs change. |

## Ephemeral resources

The same two, without anything reaching state or plan. They need OpenTofu 1.11
or Terraform 1.10, and are meant for write-only arguments.

| Ephemeral resource | What it does |
|---|---|
| [`age_identity`](docs/ephemeral-resources/identity.md) | Generates an identity, X25519 or post-quantum (`post_quantum = true`, as `age-keygen -pq`). A new one on every run. |
| [`age_encrypted`](docs/ephemeral-resources/encrypted.md) | Encrypts `plaintext` to recipients. A new ciphertext on every run. |

## Example

Keys in state:

```hcl
terraform {
  required_providers {
    age = {
      source = "aleksanderaleksic/age"
    }
  }
}

resource "random_bytes" "data_key" {
  length = 32

  lifecycle {
    prevent_destroy = true
  }
}

resource "age_identity" "backup" {}

resource "age_encrypted" "data_key" {
  plaintext  = random_bytes.data_key.hex
  recipients = [age_identity.backup.recipient]
}
```

`tofu apply -replace=age_identity.backup` rotates the identity: the same data
key is re-encrypted to the new recipient, so data encrypted under the key stays
readable.

Keys out of state, written once to a secret store through write-only arguments:

```hcl
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

resource "onepassword_item" "klio_encryption" {
  vault    = var.vault_id
  title    = "klio-encryption"
  category = "password"

  password_wo           = ephemeral.age_identity.backup.identity
  password_wo_version   = 1
  note_value_wo         = ephemeral.age_encrypted.data_key.ciphertext
  note_value_wo_version = 1
}
```

Every run generates a new identity and data key, but a write-only argument is
only sent when its version changes, so 1Password keeps the first pair. Bump
both versions together to rotate. Rotating this way replaces the data key too,
so everything encrypted with the old one becomes unreadable; to keep a data
key and rotate only its wrapping, use the resources.

## Security notes

- The resources keep identities and plaintexts in state. Use
  [state encryption](https://opentofu.org/docs/language/state/encryption/) or a
  backend you trust with secrets, or the ephemeral resources.
- The ephemeral resources keep nothing: whatever receives their values (a
  write-only argument) is the only copy.
- age encryption is randomized, which is why encryption is a resource and not a
  function: a function would produce a different ciphertext on every plan.

## Development

```sh
go build ./...
go generate ./...   # formats examples and regenerates docs/

# Acceptance tests, against OpenTofu:
TF_ACC_TERRAFORM_PATH="$(command -v tofu)" \
TF_ACC_PROVIDER_HOST=registry.opentofu.org \
TF_ACC_PROVIDER_NAMESPACE=hashicorp \
  go test ./... -count=1 -v
```

Releases are built by GoReleaser on `v*` tags and signed with GPG. The
workflow needs the `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` repository secrets.

## License

[MPL-2.0](LICENSE)
