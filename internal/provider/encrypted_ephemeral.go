package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ ephemeral.EphemeralResource                   = (*encryptedEphemeral)(nil)
	_ ephemeral.EphemeralResourceWithValidateConfig = (*encryptedEphemeral)(nil)
)

type encryptedEphemeral struct{}

type encryptedEphemeralModel struct {
	ID               types.String `tfsdk:"id"`
	Plaintext        types.String `tfsdk:"plaintext"`
	Recipients       types.List   `tfsdk:"recipients"`
	Ciphertext       types.String `tfsdk:"ciphertext"`
	CiphertextBase64 types.String `tfsdk:"ciphertext_base64"`
}

// NewEncryptedEphemeral returns the age_encrypted ephemeral resource.
func NewEncryptedEphemeral() ephemeral.EphemeralResource {
	return &encryptedEphemeral{}
}

func (e *encryptedEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_encrypted"
}

func (e *encryptedEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Encrypts `plaintext` to one or more age recipients without storing the plaintext " +
			"or the ciphertext in state or plan.\n\n" +
			"age encryption is randomized, so the ciphertext differs every time the ephemeral resource is " +
			"opened, which is on every plan and apply. Use it with ephemeral inputs (`ephemeral.age_identity`, " +
			"`ephemeral.random_bytes`) and pass the ciphertext to a write-only argument.\n\n" +
			"Requires OpenTofu 1.11 or Terraform 1.10 or later.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "SHA-256 of the binary ciphertext.",
				Computed:            true,
			},
			"plaintext": schema.StringAttribute{
				MarkdownDescription: "The data to encrypt.",
				Required:            true,
				Sensitive:           true,
			},
			"recipients": schema.ListAttribute{
				MarkdownDescription: "age recipients, X25519 (`age1...`) or post-quantum (`age1pq1...`). " +
					"Any of the matching identities can decrypt. The two kinds can't be mixed in one list.",
				ElementType: types.StringType,
				Required:    true,
			},
			"ciphertext": schema.StringAttribute{
				MarkdownDescription: "The ciphertext, ASCII-armored (`-----BEGIN AGE ENCRYPTED FILE-----`). Multi-line.",
				Computed:            true,
			},
			"ciphertext_base64": schema.StringAttribute{
				MarkdownDescription: "The binary ciphertext, base64-encoded on a single line. " +
					"Useful for stores that don't preserve newlines.",
				Computed: true,
			},
		},
	}
}

func (e *encryptedEphemeral) ValidateConfig(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	resp.Diagnostics.Append(validateRecipients(ctx, req.Config)...)
}

func (e *encryptedEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data encryptedEphemeralModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var rcptStrings []string
	resp.Diagnostics.Append(data.Recipients.ElementsAs(ctx, &rcptStrings, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := encryptToOutputs([]byte(data.Plaintext.ValueString()), rcptStrings)
	if err != nil {
		resp.Diagnostics.AddError("Encrypting with age", err.Error())
		return
	}

	data.ID = types.StringValue(out.id)
	data.Ciphertext = types.StringValue(out.armored)
	data.CiphertextBase64 = types.StringValue(out.base64)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
