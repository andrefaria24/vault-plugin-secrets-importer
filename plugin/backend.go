package plugin

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type vaultWriterFactory func(*vaultConnectionConfig) (vaultWriter, error)

type csvImporterBackend struct {
	*framework.Backend

	writerFactory             vaultWriterFactory
	awsProviderFactory        awsSecretsManagerProviderFactory
	azureProviderFactory      azureKeyVaultProviderFactory
	conjurProviderFactory     conjurProviderFactory
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func backend() *csvImporterBackend {
	var b csvImporterBackend

	b.writerFactory = newVaultWriter
	b.awsProviderFactory = newAWSSecretsManagerProvider
	b.azureProviderFactory = newAzureKeyVaultProvider
	b.conjurProviderFactory = newConjurProvider
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				configStoragePath,
			},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathConfigTest(),
			b.pathImportCSV(),
			b.pathImportAWSSecretsManager(),
			b.pathImportAzureKeyVault(),
			b.pathImportConjur(),
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}

	return &b
}

func (b *csvImporterBackend) invalidate(_ context.Context, _ string) {}

const backendHelp = `
The secrets-importer backend imports secret data from CSV files, AWS Secrets Manager,
Azure Key Vault, and CyberArk Conjur into an existing Vault KV v2 mount.

Because Vault secrets engines are isolated to their own storage barrier, this plugin
cannot write directly into another mount's storage. Instead, it calls the Vault HTTP
API using plugin configuration stored at "config".
`
