package provider

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

var testProviders = map[string]func() (tfprotov6.ProviderServer, error){
	"age": providerserver.NewProtocol6WithError(New("test")()),
}

const plaintext = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func configIdentityAndEncrypted(keepers string) string {
	return fmt.Sprintf(`
resource "age_identity" "test" {
  keepers = { rotation = %q }
}

resource "age_encrypted" "test" {
  plaintext  = %q
  recipients = [age_identity.test.recipient]
}
`, keepers, plaintext)
}

func TestAccEncryptRoundTripAndRotate(t *testing.T) {
	var firstIdentity string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: configIdentityAndEncrypted("1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("age_identity.test", "identity", regexp.MustCompile(`^AGE-SECRET-KEY-1[0-9A-Z]+$`)),
					resource.TestMatchResourceAttr("age_identity.test", "recipient", regexp.MustCompile(`^age1[0-9a-z]+$`)),
					resource.TestMatchResourceAttr("age_encrypted.test", "ciphertext", regexp.MustCompile(`^-----BEGIN AGE ENCRYPTED FILE-----\n`)),
					checkDecrypts("age_identity.test", "age_encrypted.test"),
					captureAttr("age_identity.test", "identity", &firstIdentity),
				),
			},
			// Same config again: the framework fails the step on any planned
			// change, which proves the ciphertext is stable across plans.
			{
				Config: configIdentityAndEncrypted("1"),
			},
			// Rotation: a new identity, and the same plaintext re-encrypted to it.
			{
				Config: configIdentityAndEncrypted("2"),
				Check: resource.ComposeAggregateTestCheckFunc(
					checkDecrypts("age_identity.test", "age_encrypted.test"),
					func(s *terraform.State) error {
						if got := s.RootModule().Resources["age_identity.test"].Primary.Attributes["identity"]; got == firstIdentity {
							return fmt.Errorf("identity was not rotated")
						}
						return nil
					},
				),
			},
		},
	})
}

func TestAccIdentityImport(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config:             `resource "age_identity" "test" {}`,
				ResourceName:       "age_identity.test",
				ImportState:        true,
				ImportStateId:      id.String(),
				ImportStatePersist: true,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					attrs := states[0].Attributes
					if attrs["identity"] != id.String() || attrs["recipient"] != id.Recipient().String() {
						return fmt.Errorf("imported state does not match the identity: %v", attrs)
					}
					return nil
				},
			},
			// The imported identity must be kept, not regenerated.
			{
				Config: `resource "age_identity" "test" {}`,
				Check:  resource.TestCheckResourceAttr("age_identity.test", "recipient", id.Recipient().String()),
			},
		},
	})
}

func TestAccInvalidInputs(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: `
resource "age_encrypted" "test" {
  plaintext  = "x"
  recipients = ["age1notarecipient"]
}`,
				ExpectError: regexp.MustCompile(`Invalid recipient`),
			},
			{
				Config: `
resource "age_encrypted" "test" {
  plaintext  = "x"
  recipients = []
}`,
				ExpectError: regexp.MustCompile(`No recipients`),
			},
			{
				Config:        `resource "age_identity" "test" {}`,
				ResourceName:  "age_identity.test",
				ImportState:   true,
				ImportStateId: "not-an-identity",
				ExpectError:   regexp.MustCompile(`Invalid import ID`),
			},
		},
	})
}

// checkDecrypts decrypts both ciphertext encodings with the identity in state
// and compares the result with the plaintext.
func checkDecrypts(identityAddr, encryptedAddr string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		mod := s.RootModule()
		identity, err := age.ParseX25519Identity(mod.Resources[identityAddr].Primary.Attributes["identity"])
		if err != nil {
			return err
		}
		enc := mod.Resources[encryptedAddr].Primary.Attributes

		binary, err := base64.StdEncoding.DecodeString(enc["ciphertext_base64"])
		if err != nil {
			return err
		}
		sources := map[string]io.Reader{
			"ciphertext_base64": bytes.NewReader(binary),
			"ciphertext":        armor.NewReader(strings.NewReader(enc["ciphertext"])),
		}
		for name, src := range sources {
			r, err := age.Decrypt(src, identity)
			if err != nil {
				return fmt.Errorf("decrypting %s: %w", name, err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			if string(got) != plaintext {
				return fmt.Errorf("%s decrypted to %q, want %q", name, got, plaintext)
			}
		}
		return nil
	}
}

func captureAttr(addr, attr string, dst *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		*dst = s.RootModule().Resources[addr].Primary.Attributes[attr]
		return nil
	}
}
