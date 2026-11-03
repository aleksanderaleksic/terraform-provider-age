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
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
)

// Ephemeral values never reach state, so the tests hand them to the echo
// provider, whose echo resource copies its provider's data into state.
var ephemeralTestProviders = map[string]func() (tfprotov6.ProviderServer, error){
	"age":  providerserver.NewProtocol6WithError(New("test")()),
	"echo": echoprovider.NewProviderServer(),
}

var ephemeralVersionChecks = []tfversion.TerraformVersionCheck{
	tfversion.SkipBelow(tfversion.Version1_10_0),
}

func configEphemeral(postQuantum bool) string {
	return fmt.Sprintf(`
ephemeral "age_identity" "test" {
  post_quantum = %t
}

ephemeral "age_encrypted" "test" {
  plaintext  = %q
  recipients = [ephemeral.age_identity.test.recipient]
}

provider "echo" {
  data = {
    identity          = ephemeral.age_identity.test.identity
    recipient         = ephemeral.age_identity.test.recipient
    ciphertext        = ephemeral.age_encrypted.test.ciphertext
    ciphertext_base64 = ephemeral.age_encrypted.test.ciphertext_base64
  }
}

resource "echo" "test" {}
`, postQuantum, plaintext)
}

func TestAccEphemeralRoundTrip(t *testing.T) {
	cases := []struct {
		name          string
		postQuantum   bool
		identityRegex *regexp.Regexp
		recipRegex    *regexp.Regexp
	}{
		{"x25519", false, regexp.MustCompile(`^AGE-SECRET-KEY-1[0-9A-Z]+$`), regexp.MustCompile(`^age1[0-9a-z]+$`)},
		{"post_quantum", true, regexp.MustCompile(`^AGE-SECRET-KEY-PQ-1[0-9A-Z]+$`), regexp.MustCompile(`^age1pq1[0-9a-z]+$`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: ephemeralTestProviders,
				TerraformVersionChecks:   ephemeralVersionChecks,
				Steps: []resource.TestStep{
					{
						Config: configEphemeral(tc.postQuantum),
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestMatchResourceAttr("echo.test", "data.identity", tc.identityRegex),
							resource.TestMatchResourceAttr("echo.test", "data.recipient", tc.recipRegex),
							resource.TestMatchResourceAttr("echo.test", "data.ciphertext", regexp.MustCompile(`^-----BEGIN AGE ENCRYPTED FILE-----\n`)),
							checkEchoDecrypts("echo.test"),
							checkNoAgeState(),
						),
					},
				},
			})
		})
	}
}

// A post-quantum recipient from the ephemeral identity must also work with
// the age_encrypted resource.
func TestAccEncryptedResourcePostQuantumRecipient(t *testing.T) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "age_encrypted" "test" {
  plaintext  = %q
  recipients = [%q]
}`, plaintext, id.Recipient().String()),
				Check: func(s *terraform.State) error {
					enc := s.RootModule().Resources["age_encrypted.test"].Primary.Attributes
					return decryptsTo(id, enc["ciphertext"], enc["ciphertext_base64"])
				},
			},
		},
	})
}

func TestAccEphemeralInvalidInputs(t *testing.T) {
	x25519, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}

	config := func(recipients string) string {
		return fmt.Sprintf(`
ephemeral "age_encrypted" "test" {
  plaintext  = "x"
  recipients = %s
}

provider "echo" {
  data = ephemeral.age_encrypted.test.ciphertext
}

resource "echo" "test" {}
`, recipients)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: ephemeralTestProviders,
		TerraformVersionChecks:   ephemeralVersionChecks,
		Steps: []resource.TestStep{
			{
				Config:      config(`["age1notarecipient"]`),
				ExpectError: regexp.MustCompile(`Invalid recipient`),
			},
			{
				Config:      config(`[]`),
				ExpectError: regexp.MustCompile(`No recipients`),
			},
			{
				Config:      config(fmt.Sprintf(`[%q, %q]`, x25519.Recipient().String(), hybrid.Recipient().String())),
				ExpectError: regexp.MustCompile(`Encrypting with age`),
			},
		},
	})
}

// checkEchoDecrypts decrypts both ciphertext encodings in the echo resource
// with the identity next to them and compares the result with the plaintext.
func checkEchoDecrypts(addr string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		attrs := s.RootModule().Resources[addr].Primary.Attributes
		ids, err := age.ParseIdentities(strings.NewReader(attrs["data.identity"]))
		if err != nil {
			return err
		}
		return decryptsTo(ids[0], attrs["data.ciphertext"], attrs["data.ciphertext_base64"])
	}
}

func decryptsTo(identity age.Identity, armored, b64 string) error {
	binary, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	sources := map[string]io.Reader{
		"ciphertext_base64": bytes.NewReader(binary),
		"ciphertext":        armor.NewReader(strings.NewReader(armored)),
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

// checkNoAgeState fails if anything from the age provider reached state.
func checkNoAgeState() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for addr := range s.RootModule().Resources {
			if strings.HasPrefix(addr, "age_") || strings.Contains(addr, ".age_") {
				return fmt.Errorf("%s is in state", addr)
			}
		}
		return nil
	}
}
