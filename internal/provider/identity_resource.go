package provider

import (
	"context"
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = (*identityResource)(nil)
	_ resource.ResourceWithImportState = (*identityResource)(nil)
)

type identityResource struct{}

type identityModel struct {
	ID        types.String `tfsdk:"id"`
	Identity  types.String `tfsdk:"identity"`
	Recipient types.String `tfsdk:"recipient"`
	Keepers   types.Map    `tfsdk:"keepers"`
}

// NewIdentityResource returns the age_identity resource.
func NewIdentityResource() resource.Resource {
	return &identityResource{}
}

func (r *identityResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identity"
}

func (r *identityResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Generates an age X25519 identity (private key) and its recipient (public key).\n\n" +
			"The identity is generated once and kept in state, so it stays stable across plans. " +
			"To rotate it, replace the resource (`tofu apply -replace=...`) or change `keepers`.\n\n" +
			"~> **Note:** the identity is stored in state. Use encrypted state or a backend you trust with secrets.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Same as `recipient`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"identity": schema.StringAttribute{
				MarkdownDescription: "The identity, `AGE-SECRET-KEY-1...`. This is the format of an age identity file.",
				Computed:            true,
				Sensitive:           true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"recipient": schema.StringAttribute{
				MarkdownDescription: "The recipient, `age1...`. Pass it to `age_encrypted.recipients`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"keepers": schema.MapAttribute{
				MarkdownDescription: "Arbitrary values that, when changed, generate a new identity.",
				ElementType:         types.StringType,
				Optional:            true,
				PlanModifiers:       []planmodifier.Map{mapplanmodifier.RequiresReplace()},
			},
		},
	}
}

func (r *identityResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan identityModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		resp.Diagnostics.AddError("Generating age identity", err.Error())
		return
	}

	setIdentity(&plan, id)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read is a no-op: the identity only exists in state.
func (r *identityResource) Read(context.Context, resource.ReadRequest, *resource.ReadResponse) {}

// Update is never called with a real change: keepers forces replacement and
// everything else is computed.
func (r *identityResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan identityModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete only drops the resource from state.
func (r *identityResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}

// ImportState adopts an existing identity. The import ID is the identity
// itself (AGE-SECRET-KEY-1...), so it ends up in the import command or block;
// prefer an import block fed from a sensitive source over the CLI.
func (r *identityResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := age.ParseX25519Identity(strings.TrimSpace(req.ID))
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Expected an age X25519 identity (AGE-SECRET-KEY-1...): %s", err),
		)
		return
	}

	var state identityModel
	setIdentity(&state, id)
	state.Keepers = types.MapNull(types.StringType)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func setIdentity(m *identityModel, id *age.X25519Identity) {
	recipient := id.Recipient().String()
	m.ID = types.StringValue(recipient)
	m.Identity = types.StringValue(id.String())
	m.Recipient = types.StringValue(recipient)
}
