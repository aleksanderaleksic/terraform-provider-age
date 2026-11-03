package provider

import (
	"context"

	"filippo.io/age"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ ephemeral.EphemeralResource = (*identityEphemeral)(nil)

type identityEphemeral struct{}

type identityEphemeralModel struct {
	PostQuantum types.Bool   `tfsdk:"post_quantum"`
	Identity    types.String `tfsdk:"identity"`
	Recipient   types.String `tfsdk:"recipient"`
}

// NewIdentityEphemeral returns the age_identity ephemeral resource.
func NewIdentityEphemeral() ephemeral.EphemeralResource {
	return &identityEphemeral{}
}

func (e *identityEphemeral) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identity"
}

func (e *identityEphemeral) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Generates an age identity (private key) and its recipient (public key) without " +
			"storing either in state or plan.\n\n" +
			"A new identity is generated every time the ephemeral resource is opened, which is on every plan and " +
			"apply. Pass it to a write-only argument that is only sent when its version changes, such as " +
			"`password_wo` and `password_wo_version` on `onepassword_item`: the identity is then written once, " +
			"and later runs generate one that is thrown away.\n\n" +
			"Requires OpenTofu 1.11 or Terraform 1.10 or later.",
		Attributes: map[string]schema.Attribute{
			"post_quantum": schema.BoolAttribute{
				MarkdownDescription: "Generate a post-quantum hybrid identity (ML-KEM-768 + X25519, " +
					"`age-keygen -pq`) instead of an X25519 identity. Defaults to `false`.",
				Optional: true,
			},
			"identity": schema.StringAttribute{
				MarkdownDescription: "The identity: `AGE-SECRET-KEY-1...`, or `AGE-SECRET-KEY-PQ-1...` with " +
					"`post_quantum`. This is the format of an age identity file.",
				Computed:  true,
				Sensitive: true,
			},
			"recipient": schema.StringAttribute{
				MarkdownDescription: "The recipient: `age1...`, or `age1pq1...` with `post_quantum`. " +
					"Pass it to `age_encrypted.recipients`.",
				Computed: true,
			},
		},
	}
}

func (e *identityEphemeral) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data identityEphemeralModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var identity, recipient string
	if data.PostQuantum.ValueBool() {
		id, err := age.GenerateHybridIdentity()
		if err != nil {
			resp.Diagnostics.AddError("Generating age identity", err.Error())
			return
		}
		identity, recipient = id.String(), id.Recipient().String()
	} else {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			resp.Diagnostics.AddError("Generating age identity", err.Error())
			return
		}
		identity, recipient = id.String(), id.Recipient().String()
	}

	data.Identity = types.StringValue(identity)
	data.Recipient = types.StringValue(recipient)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
