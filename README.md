# terraform-provider-age

An OpenTofu / Terraform provider for [age](https://age-encryption.org): generate
X25519 identities and encrypt data to age recipients, entirely as code.

It exists to bootstrap keys that tools expect as age files, such as the
encryption key of [Klio](https://cloudnative-pg.io/klio/) (CloudNativePG
backups), without a one-off `age-keygen` script, and to rotate them with a
plain `apply`.

## Resources

| Resource | What it does |
|---|---|
| [`age_identity`](docs/resources/identity.md) | Generates an identity (`AGE-SECRET-KEY-1...`) and its recipient (`age1...`). Stable across plans; rotate with `-replace` or `keepers`. |
| [`age_encrypted`](docs/resources/encrypted.md) | Encrypts `plaintext` to one or more recipients. Outputs ASCII-armored and single-line base64 ciphertext. Only re-encrypts when its inputs change. |

## Example

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

## Security notes

- Identities and plaintexts live in state. Use
  [state encryption](https://opentofu.org/docs/language/state/encryption/) or a
  backend you trust with secrets.
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
