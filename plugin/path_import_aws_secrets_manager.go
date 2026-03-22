package plugin

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *csvImporterBackend) pathImportAWSSecretsManager() *framework.Path {
	fields := sharedImportFields()
	fields["aws_region"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "AWS region containing the secret.",
	}
	fields["aws_profile"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Optional AWS shared config profile name.",
	}
	fields["secret_id"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "AWS Secrets Manager secret identifier or ARN.",
	}
	fields["version_id"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Optional specific secret version ID.",
	}
	fields["version_stage"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Optional staging label such as AWSCURRENT or AWSPREVIOUS.",
	}

	return &framework.Path{
		Pattern: "import/aws/secretsmanager",
		Fields:  fields,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathImportAWSSecretsManagerWrite,
			logical.UpdateOperation: b.pathImportAWSSecretsManagerWrite,
		},
		ExistenceCheck: alwaysNotFoundExistenceCheck,
		HelpSynopsis:    "Import a secret from AWS Secrets Manager into Vault KV v2.",
		HelpDescription: pathImportAWSSecretsManagerHelp,
	}
}

func (b *csvImporterBackend) pathImportAWSSecretsManagerWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	importReq, errResp := readExternalImportRequest(data)
	if errResp != nil {
		return errResp, nil
	}

	region := strings.TrimSpace(data.Get("aws_region").(string))
	if region == "" {
		return logical.ErrorResponse("aws_region is required"), nil
	}
	secretID := strings.TrimSpace(data.Get("secret_id").(string))
	if secretID == "" {
		return logical.ErrorResponse("secret_id is required"), nil
	}

	provider, err := b.awsProviderFactory(&awsSecretsManagerConfig{
		Region:  region,
		Profile: strings.TrimSpace(data.Get("aws_profile").(string)),
	})
	if err != nil {
		return nil, err
	}

	secret, err := provider.ReadSecret(ctx, &awsSecretsManagerRequest{
		SecretID:     secretID,
		VersionID:    strings.TrimSpace(data.Get("version_id").(string)),
		VersionStage: strings.TrimSpace(data.Get("version_stage").(string)),
		ParseJSON:    importReq.ParseJSON,
		RawField:     importReq.RawField,
	})
	if err != nil {
		return nil, err
	}

	return b.importExternalSecret(ctx, req, importReq, secret, data.Get("dry_run").(bool))
}

const pathImportAWSSecretsManagerHelp = `
Imports a single secret from AWS Secrets Manager into an existing Vault KV v2 mount.

If parse_json=true and the AWS secret string contains a top-level JSON object, each
JSON property becomes a Vault field. Otherwise the raw value is stored under raw_field.
`
