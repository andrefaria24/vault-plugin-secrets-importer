package plugin

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *csvImporterBackend) pathImportAzureKeyVault() *framework.Path {
	fields := sharedImportFields()
	fields["vault_url"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Azure Key Vault URL, for example https://my-vault.vault.azure.net/.",
	}
	fields["secret_name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Azure Key Vault secret name.",
	}
	fields["secret_version"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Optional Azure Key Vault secret version. Leave empty for latest.",
	}

	return &framework.Path{
		Pattern: "import/azure/keyvault",
		Fields:  fields,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathImportAzureKeyVaultWrite,
			logical.UpdateOperation: b.pathImportAzureKeyVaultWrite,
		},
		ExistenceCheck: alwaysNotFoundExistenceCheck,
		HelpSynopsis:    "Import a secret from Azure Key Vault into Vault KV v2.",
		HelpDescription: pathImportAzureKeyVaultHelp,
	}
}

func (b *csvImporterBackend) pathImportAzureKeyVaultWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	importReq, errResp := readExternalImportRequest(data)
	if errResp != nil {
		return errResp, nil
	}

	vaultURL := strings.TrimSpace(data.Get("vault_url").(string))
	if vaultURL == "" {
		return logical.ErrorResponse("vault_url is required"), nil
	}
	secretName := strings.TrimSpace(data.Get("secret_name").(string))
	if secretName == "" {
		return logical.ErrorResponse("secret_name is required"), nil
	}

	provider, err := b.azureProviderFactory(&azureKeyVaultConfig{
		VaultURL: vaultURL,
	})
	if err != nil {
		return nil, err
	}

	secret, err := provider.ReadSecret(ctx, &azureKeyVaultRequest{
		SecretName:    secretName,
		SecretVersion: strings.TrimSpace(data.Get("secret_version").(string)),
		ParseJSON:     importReq.ParseJSON,
		RawField:      importReq.RawField,
	})
	if err != nil {
		return nil, err
	}

	return b.importExternalSecret(ctx, req, importReq, secret, data.Get("dry_run").(bool))
}

const pathImportAzureKeyVaultHelp = `
Imports a single secret from Azure Key Vault into an existing Vault KV v2 mount.

If parse_json=true and the Azure secret value contains a top-level JSON object, each
JSON property becomes a Vault field. Otherwise the raw value is stored under raw_field.
`
