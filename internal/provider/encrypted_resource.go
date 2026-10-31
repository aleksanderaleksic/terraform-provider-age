package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = (*encryptedResource)(nil)
	_ resource.ResourceWithValidateConfig = (*encryptedResource)(nil)
)

type encryptedResource struct{}

type encryptedModel struct {
	ID               types.String `tfsdk:"id"`
	Plaintext        types.String `tfsdk:"plaintext"`
	Recipients       types.List   `tfsdk:"recipients"`
	Ciphertext       types.String `tfsdk:"ciphertext"`
	CiphertextBase64 types.String `tfsdk:"ciphertext_base64"`
}

// NewEncryptedResource returns the age_encrypted resource.
func NewEncryptedResource() resource.Resource {
	return &encryptedResource{}
}

func (r *encryptedResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_encrypted"
}

func (r *encryptedResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Encrypts `plaintext` to one or more age recipients.\n\n" +
			"age encryption is randomized, so this is a resource rather than a function or data source: " +
			"the ciphertext is produced once and kept in state, and only re-encrypted when `plaintext` or " +
			"`recipients` change. Re-encrypting the same plaintext to a new recipient is how an identity is rotated.\n\n" +
			"~> **Note:** `plaintext` is stored in state. Use encrypted state or a backend you trust with secrets.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "SHA-256 of the binary ciphertext.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"plaintext": schema.StringAttribute{
				MarkdownDescription: "The data to encrypt. Changing it re-encrypts.",
				Required:            true,
				Sensitive:           true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"recipients": schema.ListAttribute{
				MarkdownDescription: "age X25519 recipients (`age1...`). Any of the matching identities can decrypt. " +
					"Changing the list re-encrypts.",
				ElementType:   types.StringType,
				Required:      true,
				PlanModifiers: []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
			"ciphertext": schema.StringAttribute{
				MarkdownDescription: "The ciphertext, ASCII-armored (`-----BEGIN AGE ENCRYPTED FILE-----`). Multi-line.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"ciphertext_base64": schema.StringAttribute{
				MarkdownDescription: "The binary ciphertext, base64-encoded on a single line. " +
					"Useful for stores that don't preserve newlines.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *encryptedResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var recipients []types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("recipients"), &recipients)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if recipients != nil && len(recipients) == 0 {
		resp.Diagnostics.AddAttributeError(path.Root("recipients"), "No recipients", "At least one recipient is required.")
	}
	for i, rcpt := range recipients {
		if rcpt.IsUnknown() || rcpt.IsNull() {
			continue
		}
		if _, err := age.ParseX25519Recipient(rcpt.ValueString()); err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("recipients").AtListIndex(i), "Invalid recipient", err.Error())
		}
	}
}

func (r *encryptedResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan encryptedModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var rcptStrings []string
	resp.Diagnostics.Append(plan.Recipients.ElementsAs(ctx, &rcptStrings, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ciphertext, err := encrypt([]byte(plan.Plaintext.ValueString()), rcptStrings)
	if err != nil {
		resp.Diagnostics.AddError("Encrypting with age", err.Error())
		return
	}

	armored, err := armorEncode(ciphertext)
	if err != nil {
		resp.Diagnostics.AddError("Armoring ciphertext", err.Error())
		return
	}

	sum := sha256.Sum256(ciphertext)
	plan.ID = types.StringValue(hex.EncodeToString(sum[:]))
	plan.Ciphertext = types.StringValue(armored)
	plan.CiphertextBase64 = types.StringValue(base64.StdEncoding.EncodeToString(ciphertext))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read is a no-op: the ciphertext only exists in state.
func (r *encryptedResource) Read(context.Context, resource.ReadRequest, *resource.ReadResponse) {}

// Update is never called with a real change: every input forces replacement.
func (r *encryptedResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan encryptedModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete only drops the resource from state.
func (r *encryptedResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}

func encrypt(plaintext []byte, recipients []string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	rcpts := make([]age.Recipient, 0, len(recipients))
	for _, s := range recipients {
		rcpt, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, fmt.Errorf("parsing recipient %q: %w", s, err)
		}
		rcpts = append(rcpts, rcpt)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rcpts...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func armorEncode(ciphertext []byte) (string, error) {
	var buf bytes.Buffer
	w := armor.NewWriter(&buf)
	if _, err := io.Copy(w, bytes.NewReader(ciphertext)); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}

	return buf.String(), nil
}
