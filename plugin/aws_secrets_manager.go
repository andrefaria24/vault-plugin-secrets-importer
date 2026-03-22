package plugin

import (
	"context"
	"fmt"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type awsSecretsManagerProviderFactory func(*awsSecretsManagerConfig) (awsSecretsManagerProvider, error)

type awsSecretsManagerConfig struct {
	Region  string
	Profile string
}

type awsSecretsManagerRequest struct {
	SecretID     string
	VersionID    string
	VersionStage string
	ParseJSON    bool
	RawField     string
}

type awsSecretsManagerProvider interface {
	ReadSecret(context.Context, *awsSecretsManagerRequest) (*externalSecret, error)
}

type awsSecretsManagerClient struct {
	client *secretsmanager.Client
}

func newAWSSecretsManagerProvider(cfg *awsSecretsManagerConfig) (awsSecretsManagerProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("aws configuration is missing")
	}
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, fmt.Errorf("aws region is required")
	}

	loadOptions := make([]func(*awsconfig.LoadOptions) error, 0, 2)
	loadOptions = append(loadOptions, awsconfig.WithRegion(strings.TrimSpace(cfg.Region)))
	if strings.TrimSpace(cfg.Profile) != "" {
		loadOptions = append(loadOptions, awsconfig.WithSharedConfigProfile(strings.TrimSpace(cfg.Profile)))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load AWS SDK config: %w", err)
	}

	return &awsSecretsManagerClient{
		client: secretsmanager.NewFromConfig(awsCfg),
	}, nil
}

func (c *awsSecretsManagerClient) ReadSecret(ctx context.Context, req *awsSecretsManagerRequest) (*externalSecret, error) {
	if req == nil {
		return nil, fmt.Errorf("aws request is missing")
	}
	if strings.TrimSpace(req.SecretID) == "" {
		return nil, fmt.Errorf("secret_id is required")
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: &req.SecretID,
	}
	if strings.TrimSpace(req.VersionID) != "" {
		input.VersionId = &req.VersionID
	}
	if strings.TrimSpace(req.VersionStage) != "" {
		input.VersionStage = &req.VersionStage
	}

	resp, err := c.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("read AWS Secrets Manager secret %q: %w", req.SecretID, err)
	}

	rawString := ""
	if resp.SecretString != nil {
		rawString = *resp.SecretString
	}
	data, err := normalizeExternalSecret(rawString, resp.SecretBinary, req.ParseJSON, req.RawField)
	if err != nil {
		return nil, err
	}

	version := ""
	if resp.VersionId != nil {
		version = *resp.VersionId
	}

	return &externalSecret{
		SourceType: "aws-secretsmanager",
		SourceID:   req.SecretID,
		Version:    version,
		Data:       data,
		Metadata: map[string]interface{}{
			"provider":      "aws-secretsmanager",
			"secret_id":     req.SecretID,
			"version_id":    version,
			"version_stages": resp.VersionStages,
		},
	}, nil
}
