package plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

func (b *csvImporterBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: configStoragePath,
		Fields: map[string]*framework.FieldSchema{
			"address": {
				Type:        framework.TypeString,
				Description: "Vault address used by the plugin when writing to the destination KV v2 mount.",
			},
			"token": {
				Type:        framework.TypeString,
				Description: "Vault token used by the plugin. Prefer token_file when possible.",
			},
			"token_file": {
				Type:        framework.TypeString,
				Description: "Local file path containing a Vault token for the plugin to use.",
			},
			"default_namespace": {
				Type:        framework.TypeString,
				Description: "Optional default namespace used when import requests do not specify namespace. Enterprise and HCP only.",
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "Optional PEM-encoded CA certificate contents.",
			},
			"ca_cert_file": {
				Type:        framework.TypeString,
				Description: "Optional path to a PEM-encoded CA certificate file.",
			},
			"ca_path": {
				Type:        framework.TypeString,
				Description: "Optional path to a directory containing CA certificates.",
			},
			"tls_server_name": {
				Type:        framework.TypeString,
				Description: "Optional TLS server name override.",
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Skip TLS certificate verification. Avoid this outside local development.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathConfigWrite,
			logical.UpdateOperation: b.pathConfigWrite,
			logical.ReadOperation:   b.pathConfigRead,
			logical.DeleteOperation: b.pathConfigDelete,
		},
		ExistenceCheck: alwaysNotFoundExistenceCheck,
		HelpSynopsis:    "Configure how the plugin talks back to Vault.",
		HelpDescription: pathConfigHelp,
	}
}

func (b *csvImporterBackend) pathConfigTest() *framework.Path {
	return &framework.Path{
		Pattern: "config/test",
		Fields: map[string]*framework.FieldSchema{
			"namespace": {
				Type:        framework.TypeString,
				Description: "Optional namespace override used for the connectivity test. Leave empty on Vault Community Edition.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigTestRead,
			logical.UpdateOperation: b.pathConfigTestRead,
		},
		HelpSynopsis:    "Validate the plugin's configured Vault API connectivity.",
		HelpDescription: pathConfigTestHelp,
	}
}

func (b *csvImporterBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := loadConnectionConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	tokenSource := ""
	switch {
	case strings.TrimSpace(cfg.Token) != "":
		tokenSource = "inline"
	case strings.TrimSpace(cfg.TokenFile) != "":
		tokenSource = "file"
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address":           cfg.Address,
			"default_namespace": cfg.DefaultNS,
			"token_source":      tokenSource,
			"token_file":        cfg.TokenFile,
			"ca_cert_file":      cfg.CACertFile,
			"ca_path":           cfg.CAPath,
			"tls_server_name":   cfg.TLSServerName,
			"tls_skip_verify":   cfg.TLSSkipVerify,
			"has_inline_ca":     strings.TrimSpace(cfg.CACert) != "",
		},
	}, nil
}

func (b *csvImporterBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := loadConnectionConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &vaultConnectionConfig{}
	}

	if value, ok := data.GetOk("address"); ok {
		cfg.Address = strings.TrimSpace(value.(string))
	}
	if value, ok := data.GetOk("token"); ok {
		cfg.Token = strings.TrimSpace(value.(string))
	}
	if value, ok := data.GetOk("token_file"); ok {
		cfg.TokenFile = strings.TrimSpace(value.(string))
	}
	if value, ok := data.GetOk("default_namespace"); ok {
		cfg.DefaultNS = cleanNamespace(value.(string))
	}
	if value, ok := data.GetOk("ca_cert"); ok {
		cfg.CACert = value.(string)
	}
	if value, ok := data.GetOk("ca_cert_file"); ok {
		cfg.CACertFile = strings.TrimSpace(value.(string))
	}
	if value, ok := data.GetOk("ca_path"); ok {
		cfg.CAPath = strings.TrimSpace(value.(string))
	}
	if value, ok := data.GetOk("tls_server_name"); ok {
		cfg.TLSServerName = strings.TrimSpace(value.(string))
	}
	if value, ok := data.GetOk("tls_skip_verify"); ok {
		cfg.TLSSkipVerify = value.(bool)
	}

	if strings.TrimSpace(cfg.Address) == "" {
		return logical.ErrorResponse("address is required"), nil
	}
	if strings.TrimSpace(cfg.Token) == "" && strings.TrimSpace(cfg.TokenFile) == "" {
		return logical.ErrorResponse("one of token or token_file must be set"), nil
	}
	if strings.TrimSpace(cfg.Token) != "" && strings.TrimSpace(cfg.TokenFile) != "" {
		return logical.ErrorResponse("set token or token_file, not both"), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		return nil, fmt.Errorf("encode plugin config: %w", err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("persist plugin config: %w", err)
	}

	return b.pathConfigRead(ctx, req, data)
}

func (b *csvImporterBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, fmt.Errorf("delete plugin config: %w", err)
	}

	return nil, nil
}

func loadConnectionConfig(ctx context.Context, storage logical.Storage) (*vaultConnectionConfig, error) {
	entry, err := storage.Get(ctx, configStoragePath)
	if err != nil {
		return nil, fmt.Errorf("read plugin config: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	var cfg vaultConnectionConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("decode plugin config: %w", err)
	}

	return &cfg, nil
}

func (b *csvImporterBackend) pathConfigTestRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := loadConnectionConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("plugin config is missing; write to config before testing"), nil
	}

	writer, err := b.writerFactory(cfg)
	if err != nil {
		return nil, err
	}

	namespace := cleanNamespace(data.Get("namespace").(string))
	status, err := writer.CheckConnection(ctx, namespace)
	if err != nil {
		return nil, err
	}

	status["community_mode"] = namespace == "" && cfg.DefaultNS == ""
	return &logical.Response{Data: status}, nil
}

const pathConfigHelp = `
The config endpoint stores how this plugin authenticates back to Vault's HTTP API.

Because Vault passes a salted and hashed client token to logical backends, the plugin
cannot reuse the caller's raw token for writes into another mount. Configure a token
or token_file with policy allowing writes to the destination KV v2 paths.
`

const pathConfigTestHelp = `
The config/test endpoint validates that the plugin can:

1. Reach the configured Vault address.
2. Authenticate with the configured token or token_file.
3. Resolve the requested namespace if one is supplied.

This is useful before running an import job, especially when targeting a Vault 1.21.4+
cluster or switching between Community Edition and Enterprise namespaces.
`
