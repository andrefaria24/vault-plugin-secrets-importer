package plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

type azureKeyVaultProviderFactory func(*azureKeyVaultConfig) (azureKeyVaultProvider, error)

type azureKeyVaultConfig struct {
	VaultURL string
}

type azureKeyVaultRequest struct {
	SecretName    string
	SecretVersion string
	ParseJSON     bool
	RawField      string
}

type azureKeyVaultProvider interface {
	ReadSecret(context.Context, *azureKeyVaultRequest) (*externalSecret, error)
}

type azureKeyVaultClient struct {
	client   *azsecrets.Client
	vaultURL string
}

func newAzureKeyVaultProvider(cfg *azureKeyVaultConfig) (azureKeyVaultProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("azure configuration is missing")
	}
	if strings.TrimSpace(cfg.VaultURL) == "" {
		return nil, fmt.Errorf("vault_url is required")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure credential: %w", err)
	}

	client, err := azsecrets.NewClient(strings.TrimSpace(cfg.VaultURL), cred, nil)
	if err != nil {
		return nil, fmt.Errorf("create Azure Key Vault client: %w", err)
	}

	return &azureKeyVaultClient{
		client:   client,
		vaultURL: strings.TrimSpace(cfg.VaultURL),
	}, nil
}

func (c *azureKeyVaultClient) ReadSecret(ctx context.Context, req *azureKeyVaultRequest) (*externalSecret, error) {
	if req == nil {
		return nil, fmt.Errorf("azure request is missing")
	}
	if strings.TrimSpace(req.SecretName) == "" {
		return nil, fmt.Errorf("secret_name is required")
	}

	resp, err := c.client.GetSecret(ctx, req.SecretName, req.SecretVersion, nil)
	if err != nil {
		return nil, fmt.Errorf("read Azure Key Vault secret %q: %w", req.SecretName, err)
	}
	if resp.Value == nil {
		return nil, fmt.Errorf("azure key vault secret %q did not contain a value", req.SecretName)
	}

	data, err := normalizeExternalSecret(*resp.Value, nil, req.ParseJSON, req.RawField)
	if err != nil {
		return nil, err
	}

	version := ""
	if resp.ID != nil {
		version = resp.ID.Version()
	}

	return &externalSecret{
		SourceType: "azure-keyvault",
		SourceID:   req.SecretName,
		Version:    version,
		Data:       data,
		Metadata: map[string]interface{}{
			"provider":       "azure-keyvault",
			"vault_url":      c.vaultURL,
			"secret_name":    req.SecretName,
			"secret_version": version,
		},
	}, nil
}
