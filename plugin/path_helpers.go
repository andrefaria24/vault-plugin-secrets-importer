package plugin

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// These endpoints are write-only operations; they never represent a stored object
// that Vault should treat as pre-existing for create/update routing.
func alwaysNotFoundExistenceCheck(context.Context, *logical.Request, *framework.FieldData) (bool, error) {
	return false, nil
}
