package plugin

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *csvImporterBackend) pathImportConjur() *framework.Path {
	fields := sharedImportFields()
	fields["appliance_url"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "CyberArk Conjur appliance URL, for example https://conjur.example.com.",
	}
	fields["account"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Conjur account name.",
	}
	fields["login"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Conjur identity login, for example host/my-app or admin.",
	}
	fields["api_key"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Conjur API key for the supplied login.",
	}
	fields["variable_id"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Conjur variable identifier to retrieve.",
	}
	fields["ssl_cert"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Optional PEM-encoded Conjur CA certificate contents.",
	}
	fields["ssl_cert_file"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Optional path to a PEM-encoded Conjur CA certificate file on the plugin host.",
	}
	fields["authn_type"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Optional Conjur authenticator type. Leave empty for the default authn flow.",
	}
	fields["service_id"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Optional Conjur authenticator service ID.",
	}

	return &framework.Path{
		Pattern: "import/cyberark/conjur",
		Fields:  fields,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathImportConjurWrite,
			logical.UpdateOperation: b.pathImportConjurWrite,
		},
		ExistenceCheck: alwaysNotFoundExistenceCheck,
		HelpSynopsis:    "Import a secret from CyberArk Conjur into Vault KV v2.",
		HelpDescription: pathImportConjurHelp,
	}
}

func (b *csvImporterBackend) pathImportConjurWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	importReq, errResp := readExternalImportRequest(data)
	if errResp != nil {
		return errResp, nil
	}

	applianceURL := strings.TrimSpace(data.Get("appliance_url").(string))
	if applianceURL == "" {
		return logical.ErrorResponse("appliance_url is required"), nil
	}
	account := strings.TrimSpace(data.Get("account").(string))
	if account == "" {
		return logical.ErrorResponse("account is required"), nil
	}
	login := strings.TrimSpace(data.Get("login").(string))
	if login == "" {
		return logical.ErrorResponse("login is required"), nil
	}
	apiKey := strings.TrimSpace(data.Get("api_key").(string))
	if apiKey == "" {
		return logical.ErrorResponse("api_key is required"), nil
	}
	variableID := strings.TrimSpace(data.Get("variable_id").(string))
	if variableID == "" {
		return logical.ErrorResponse("variable_id is required"), nil
	}

	provider, err := b.conjurProviderFactory(&conjurConfig{
		ApplianceURL: applianceURL,
		Account:      account,
		Login:        login,
		APIKey:       apiKey,
		SSLCert:      data.Get("ssl_cert").(string),
		SSLCertPath:  strings.TrimSpace(data.Get("ssl_cert_file").(string)),
		AuthnType:    strings.TrimSpace(data.Get("authn_type").(string)),
		ServiceID:    strings.TrimSpace(data.Get("service_id").(string)),
	})
	if err != nil {
		return nil, err
	}

	secret, err := provider.ReadSecret(ctx, &conjurRequest{
		VariableID: variableID,
		ParseJSON:  importReq.ParseJSON,
		RawField:   importReq.RawField,
	})
	if err != nil {
		return nil, err
	}

	return b.importExternalSecret(ctx, req, importReq, secret, data.Get("dry_run").(bool))
}

const pathImportConjurHelp = `
Imports a single secret from CyberArk Conjur into an existing Vault KV v2 mount.

This first implementation uses Conjur login and API key authentication. If parse_json=true
and the Conjur variable contains a top-level JSON object, each JSON property becomes a Vault
field. Otherwise the raw value is stored under raw_field.
`
