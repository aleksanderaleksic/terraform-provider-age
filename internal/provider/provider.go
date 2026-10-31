// Package provider implements a Terraform/OpenTofu provider for age
// (https://age-encryption.org): generating X25519 identities and encrypting
// data to age recipients.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.Provider = (*ageProvider)(nil)

type ageProvider struct {
	version string
}

// New returns a constructor for the provider, as expected by providerserver.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &ageProvider{version: version}
	}
}

func (p *ageProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "age"
	resp.Version = p.version
}

func (p *ageProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Generate [age](https://age-encryption.org) X25519 identities and encrypt data to age recipients. " +
			"Everything happens locally; the provider takes no configuration.",
	}
}

func (p *ageProvider) Configure(context.Context, provider.ConfigureRequest, *provider.ConfigureResponse) {
}

func (p *ageProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewIdentityResource,
		NewEncryptedResource,
	}
}

func (p *ageProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}
