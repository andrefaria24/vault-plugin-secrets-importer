package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type fakeVaultWriter struct {
	requests []vaultWriteRequest
	status   map[string]interface{}
}

type fakeAWSSecretsManagerProvider struct {
	secret *externalSecret
}

func (p *fakeAWSSecretsManagerProvider) ReadSecret(_ context.Context, _ *awsSecretsManagerRequest) (*externalSecret, error) {
	return p.secret, nil
}

type fakeAzureKeyVaultProvider struct {
	secret *externalSecret
}

func (p *fakeAzureKeyVaultProvider) ReadSecret(_ context.Context, _ *azureKeyVaultRequest) (*externalSecret, error) {
	return p.secret, nil
}

type fakeConjurProvider struct {
	secret *externalSecret
}

func (p *fakeConjurProvider) ReadSecret(_ context.Context, _ *conjurRequest) (*externalSecret, error) {
	return p.secret, nil
}

func (w *fakeVaultWriter) WriteSecret(_ context.Context, req vaultWriteRequest) error {
	w.requests = append(w.requests, req)
	return nil
}

func (w *fakeVaultWriter) CheckConnection(_ context.Context, _ string) (map[string]interface{}, error) {
	if w.status == nil {
		w.status = map[string]interface{}{"token_lookup": true}
	}
	return w.status, nil
}

func TestPathImportCSVDryRun(t *testing.T) {
	b := backend()
	storage := &logical.InmemStorage{}

	resp, err := b.pathImportCSVWrite(context.Background(), &logical.Request{Storage: storage}, &framework.FieldData{
		Raw: map[string]interface{}{
			"csv":               "path,username,password\napps/dev/db,svc-user,s3cr3t\n",
			"kv_mount":          "secret",
			"skip_empty_values": true,
			"trim_space":        true,
			"dry_run":           true,
		},
		Schema: b.pathImportCSV().Fields,
	})
	if err != nil {
		t.Fatalf("pathImportCSVWrite returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	if got, want := resp.Data["imported_secrets"], 1; got != want {
		t.Fatalf("imported_secrets mismatch: got %v want %v", got, want)
	}
}

func TestPathImportCSVWritesSecrets(t *testing.T) {
	b := backend()
	storage := &logical.InmemStorage{}

	fakeWriter := &fakeVaultWriter{}
	b.writerFactory = func(*vaultConnectionConfig) (vaultWriter, error) {
		return fakeWriter, nil
	}

	if _, err := b.pathConfigWrite(context.Background(), &logical.Request{Storage: storage}, &framework.FieldData{
		Raw: map[string]interface{}{
			"address": "https://vault.example.com",
			"token":   "s.test-token",
		},
		Schema: b.pathConfig().Fields,
	}); err != nil {
		t.Fatalf("pathConfigWrite returned error: %v", err)
	}

	_, err := b.pathImportCSVWrite(context.Background(), &logical.Request{Storage: storage}, &framework.FieldData{
		Raw: map[string]interface{}{
			"csv":               "path,username,password\napps/dev/db,svc-user,s3cr3t\n",
			"kv_mount":          "secret",
			"namespace":         "admin/team-a",
			"skip_empty_values": true,
			"trim_space":        true,
			"dry_run":           false,
		},
		Schema: b.pathImportCSV().Fields,
	})
	if err != nil {
		t.Fatalf("pathImportCSVWrite returned error: %v", err)
	}

	if got, want := len(fakeWriter.requests), 1; got != want {
		t.Fatalf("request count mismatch: got %d want %d", got, want)
	}
	if got, want := fakeWriter.requests[0].Namespace, "admin/team-a"; got != want {
		t.Fatalf("namespace mismatch: got %q want %q", got, want)
	}
	if got, want := fakeWriter.requests[0].Mount, "secret"; got != want {
		t.Fatalf("mount mismatch: got %q want %q", got, want)
	}
	if got, want := fakeWriter.requests[0].Path, "apps/dev/db"; got != want {
		t.Fatalf("path mismatch: got %q want %q", got, want)
	}
	if got, want := fakeWriter.requests[0].WriteMode, writeModePut; got != want {
		t.Fatalf("write mode mismatch: got %q want %q", got, want)
	}
	if got, want := fakeWriter.requests[0].CAS, -1; got != want {
		t.Fatalf("cas mismatch: got %d want %d", got, want)
	}
}

func TestPathImportCSVPassesPatchAndCAS(t *testing.T) {
	b := backend()
	storage := &logical.InmemStorage{}

	fakeWriter := &fakeVaultWriter{}
	b.writerFactory = func(*vaultConnectionConfig) (vaultWriter, error) {
		return fakeWriter, nil
	}

	if _, err := b.pathConfigWrite(context.Background(), &logical.Request{Storage: storage}, &framework.FieldData{
		Raw: map[string]interface{}{
			"address": "https://vault.example.com",
			"token":   "s.test-token",
		},
		Schema: b.pathConfig().Fields,
	}); err != nil {
		t.Fatalf("pathConfigWrite returned error: %v", err)
	}

	_, err := b.pathImportCSVWrite(context.Background(), &logical.Request{Storage: storage}, &framework.FieldData{
		Raw: map[string]interface{}{
			"csv":               "path,username\napps/dev/db,svc-user\n",
			"kv_mount":          "secret",
			"skip_empty_values": true,
			"trim_space":        true,
			"dry_run":           false,
			"write_mode":        "patch",
			"cas":               0,
		},
		Schema: b.pathImportCSV().Fields,
	})
	if err != nil {
		t.Fatalf("pathImportCSVWrite returned error: %v", err)
	}

	if got, want := fakeWriter.requests[0].WriteMode, writeModePatch; got != want {
		t.Fatalf("write mode mismatch: got %q want %q", got, want)
	}
	if got, want := fakeWriter.requests[0].CAS, 0; got != want {
		t.Fatalf("cas mismatch: got %d want %d", got, want)
	}
}

func TestPathConfigTestRead(t *testing.T) {
	b := backend()
	storage := &logical.InmemStorage{}

	fakeWriter := &fakeVaultWriter{
		status: map[string]interface{}{
			"version":      "1.21.4",
			"token_lookup": true,
		},
	}
	b.writerFactory = func(*vaultConnectionConfig) (vaultWriter, error) {
		return fakeWriter, nil
	}

	if _, err := b.pathConfigWrite(context.Background(), &logical.Request{Storage: storage}, &framework.FieldData{
		Raw: map[string]interface{}{
			"address": "https://vault.example.com",
			"token":   "s.test-token",
		},
		Schema: b.pathConfig().Fields,
	}); err != nil {
		t.Fatalf("pathConfigWrite returned error: %v", err)
	}

	resp, err := b.pathConfigTestRead(context.Background(), &logical.Request{Storage: storage}, &framework.FieldData{
		Raw: map[string]interface{}{
			"namespace": "",
		},
		Schema: b.pathConfigTest().Fields,
	})
	if err != nil {
		t.Fatalf("pathConfigTestRead returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	if got, want := resp.Data["version"], "1.21.4"; got != want {
		t.Fatalf("version mismatch: got %v want %v", got, want)
	}
}

func TestPathImportAWSSecretsManagerDryRun(t *testing.T) {
	b := backend()
	b.awsProviderFactory = func(*awsSecretsManagerConfig) (awsSecretsManagerProvider, error) {
		return &fakeAWSSecretsManagerProvider{
			secret: &externalSecret{
				SourceType: "aws-secretsmanager",
				SourceID:   "prod/db",
				Version:    "v1",
				Data: map[string]interface{}{
					"username": "svc-user",
					"password": "s3cr3t",
				},
			},
		}, nil
	}

	resp, err := b.pathImportAWSSecretsManagerWrite(context.Background(), &logical.Request{Storage: &logical.InmemStorage{}}, &framework.FieldData{
		Raw: map[string]interface{}{
			"aws_region":       "us-east-1",
			"secret_id":        "prod/db",
			"kv_mount":         "secret",
			"destination_path": "imports/aws/prod-db",
			"dry_run":          true,
			"parse_json":       true,
			"raw_field":        defaultRawField,
			"write_mode":       writeModePut,
			"cas":              -1,
		},
		Schema: b.pathImportAWSSecretsManager().Fields,
	})
	if err != nil {
		t.Fatalf("pathImportAWSSecretsManagerWrite returned error: %v", err)
	}
	if got, want := resp.Data["source_type"], "aws-secretsmanager"; got != want {
		t.Fatalf("source_type mismatch: got %v want %v", got, want)
	}
	if got, want := resp.Data["destination_path"], "imports/aws/prod-db"; got != want {
		t.Fatalf("destination_path mismatch: got %v want %v", got, want)
	}
}

func TestPathImportAzureKeyVaultWritesSecret(t *testing.T) {
	b := backend()
	storage := &logical.InmemStorage{}

	fakeWriter := &fakeVaultWriter{}
	b.writerFactory = func(*vaultConnectionConfig) (vaultWriter, error) {
		return fakeWriter, nil
	}
	b.azureProviderFactory = func(*azureKeyVaultConfig) (azureKeyVaultProvider, error) {
		return &fakeAzureKeyVaultProvider{
			secret: &externalSecret{
				SourceType: "azure-keyvault",
				SourceID:   "db-password",
				Version:    "123456",
				Data: map[string]interface{}{
					"value": "s3cr3t",
				},
				Metadata: map[string]interface{}{
					"provider": "azure-keyvault",
				},
			},
		}, nil
	}

	if _, err := b.pathConfigWrite(context.Background(), &logical.Request{Storage: storage}, &framework.FieldData{
		Raw: map[string]interface{}{
			"address": "https://vault.example.com",
			"token":   "s.test-token",
		},
		Schema: b.pathConfig().Fields,
	}); err != nil {
		t.Fatalf("pathConfigWrite returned error: %v", err)
	}

	resp, err := b.pathImportAzureKeyVaultWrite(context.Background(), &logical.Request{Storage: storage}, &framework.FieldData{
		Raw: map[string]interface{}{
			"vault_url":               "https://example.vault.azure.net/",
			"secret_name":             "db-password",
			"kv_mount":                "secret",
			"destination_path":        "imports/azure/db-password",
			"dry_run":                 false,
			"parse_json":              false,
			"raw_field":               defaultRawField,
			"write_mode":              writeModePatch,
			"cas":                     0,
			"include_source_metadata": true,
		},
		Schema: b.pathImportAzureKeyVault().Fields,
	})
	if err != nil {
		t.Fatalf("pathImportAzureKeyVaultWrite returned error: %v", err)
	}
	if got, want := len(fakeWriter.requests), 1; got != want {
		t.Fatalf("request count mismatch: got %d want %d", got, want)
	}
	if got, want := fakeWriter.requests[0].Path, "imports/azure/db-password"; got != want {
		t.Fatalf("path mismatch: got %q want %q", got, want)
	}
	if got, want := fakeWriter.requests[0].WriteMode, writeModePatch; got != want {
		t.Fatalf("write mode mismatch: got %q want %q", got, want)
	}
	if got, want := resp.Data["included_metadata"], true; got != want {
		t.Fatalf("included_metadata mismatch: got %v want %v", got, want)
	}
}

func TestPathImportConjurDryRun(t *testing.T) {
	b := backend()
	b.conjurProviderFactory = func(*conjurConfig) (conjurProvider, error) {
		return &fakeConjurProvider{
			secret: &externalSecret{
				SourceType: "cyberark-conjur",
				SourceID:   "data/prod/app/db-password",
				Data: map[string]interface{}{
					"value": "s3cr3t",
				},
			},
		}, nil
	}

	resp, err := b.pathImportConjurWrite(context.Background(), &logical.Request{Storage: &logical.InmemStorage{}}, &framework.FieldData{
		Raw: map[string]interface{}{
			"appliance_url":    "https://conjur.example.com",
			"account":          "default",
			"login":            "host/data/prod/app",
			"api_key":          "secret-api-key",
			"variable_id":      "data/prod/app/db-password",
			"kv_mount":         "secret",
			"destination_path": "imports/conjur/db-password",
			"dry_run":          true,
			"parse_json":       false,
			"raw_field":        defaultRawField,
			"write_mode":       writeModePut,
			"cas":              -1,
		},
		Schema: b.pathImportConjur().Fields,
	})
	if err != nil {
		t.Fatalf("pathImportConjurWrite returned error: %v", err)
	}
	if got, want := resp.Data["source_type"], "cyberark-conjur"; got != want {
		t.Fatalf("source_type mismatch: got %v want %v", got, want)
	}
	if got, want := resp.Data["destination_path"], "imports/conjur/db-password"; got != want {
		t.Fatalf("destination_path mismatch: got %v want %v", got, want)
	}
}
