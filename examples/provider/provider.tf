terraform {
  required_providers {
    age = {
      source = "aleksanderaleksic/age"
    }
  }
}

# The provider takes no configuration.
provider "age" {}
