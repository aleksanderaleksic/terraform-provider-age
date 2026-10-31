package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/aleksanderaleksic/terraform-provider-age/internal/provider"
)

// Format examples and regenerate docs/ from the schema and examples/.
//go:generate tofu fmt -recursive ./examples/
//go:generate go tool tfplugindocs generate --provider-name age

// version is set by goreleaser at build time.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.opentofu.org/aleksanderaleksic/age",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
