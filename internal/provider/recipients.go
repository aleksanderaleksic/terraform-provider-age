package provider

import (
	"context"
	"strings"

	"filippo.io/age"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// parseRecipient accepts both recipient types the provider generates:
// post-quantum hybrid (age1pq1...) and X25519 (age1...).
func parseRecipient(s string) (age.Recipient, error) {
	if strings.HasPrefix(s, "age1pq1") {
		return age.ParseHybridRecipient(s)
	}
	return age.ParseX25519Recipient(s)
}

// validateRecipients checks the recipients attribute of an age_encrypted
// configuration, shared by the resource and the ephemeral resource.
func validateRecipients(ctx context.Context, config tfsdk.Config) diag.Diagnostics {
	var diags diag.Diagnostics

	var recipients []types.String
	diags.Append(config.GetAttribute(ctx, path.Root("recipients"), &recipients)...)
	if diags.HasError() {
		return diags
	}

	if recipients != nil && len(recipients) == 0 {
		diags.AddAttributeError(path.Root("recipients"), "No recipients", "At least one recipient is required.")
	}
	for i, rcpt := range recipients {
		if rcpt.IsUnknown() || rcpt.IsNull() {
			continue
		}
		if _, err := parseRecipient(rcpt.ValueString()); err != nil {
			diags.AddAttributeError(path.Root("recipients").AtListIndex(i), "Invalid recipient", err.Error())
		}
	}

	return diags
}
