# vault-plugin-secrets-importer

This is a HashiCorp Vault plugin that imports data from external sources into an existing Vault KV v2 mount.

The current implementation supports:

- Entries within CSV files
- AWS Secrets Manager
- Azure Key Vault
- CyberArk Conjur

The goal of this plugin is to simplify migrations into Vault without requiring operators to manually read secrets from external systems and rewrite them one-by-one into KV v2.

Because Vault secrets engines are isolated to their own storage barrier, the plugin cannot write directly into another mount's storage. Instead, it stores connection settings under `config` and writes to the target KV v2 mount through Vault's HTTP API.

## Installation

### Using pre-built releases

You can find pre-built releases of the plugin [here](https://github.com/andrefaria24/vault-plugin-secrets-importer/releases). Once you have downloaded the latest archive corresponding to your target OS, uncompress it to retrieve the vault-plugin-secrets-importer binary file. Move this to each of your Vault nodes where they store plugins.

### From Source

If you want to build the plugin from source, run:

```bash
go mod tidy
go build -o vault-plugin-secrets-importer ./cmd/vault-plugin-secrets-importer
```

## Configuration

Copy the plugin binary into a directory configured as Vault's [plugin_directory](https://developer.hashicorp.com/vault/docs/configuration#plugin_directory):

```hcl
plugin_directory = "path/to/plugin/directory"
```

Start Vault with that configuration:

```bash
vault server -config=path/to/vault/config.hcl
```

Register the plugin in the [plugin catalog](https://developer.hashicorp.com/vault/docs/plugins#plugin-catalog):

```bash
vault plugin register -sha256="$(sha256sum vault-plugin-secrets-importer | cut -d ' ' -f1)" secret vault-plugin-secrets-importer
```

Enable the plugin:

```bash
vault secrets enable -path=csv-importer -plugin-name=vault-plugin-secrets-importer plugin
```

Enable a destination KV v2 mount if needed:

```bash
vault secrets enable -path=secret -version=2 kv
```

Configure how the plugin talks back to Vault:

```bash
vault write csv-importer/config \
  address="https://vault.example.com:8200" \
  token_file="/etc/vault/importer.token"
```

You can also provide an inline token:

```bash
vault write csv-importer/config \
  address="https://vault.example.com:8200" \
  token="hvs.xxxxx"
```

Enterprise and HCP users can set a default namespace:

```bash
vault write csv-importer/config \
  address="https://vault.example.com:8200" \
  token_file="/etc/vault/importer.token" \
  default_namespace="admin"
```

Validate connectivity before importing:

```bash
vault write -f csv-importer/config/test
```

Namespace validation example:

```bash
vault write csv-importer/config/test namespace="admin/team-a"
```

Notes:

- Use `token_file` instead of inline `token` when possible.
- The configured token must be allowed to write to the destination KV v2 paths.
- On Vault Community Edition, leave `namespace` empty.
- Minimum tested Vault target is `1.21.4`.

## Usage

### CSV

Per-row secret mode:

```csv
path,username,password
apps/dev/db,svc-user,s3cr3t
apps/dev/api,api-user,token-123
```

Import it with:

```bash
vault write csv-importer/import/csv \
  kv_mount="secret" \
  base_path="applications" \
  write_mode="put" \
  csv=@./examples/secrets-row-mode.csv
```

Fixed-secret mode:

```csv
key,value
username,svc-user
password,s3cr3t
```

Import it with:

```bash
vault write csv-importer/import/csv \
  kv_mount="secret" \
  secret_path="apps/dev/db" \
  cas=0 \
  csv=@./examples/secrets-fixed-secret.csv
```

Dry-run example:

```bash
vault write csv-importer/import/csv \
  kv_mount="secret" \
  base_path="applications" \
  write_mode="put" \
  dry_run=true \
  csv=@./examples/secrets-row-mode.csv
```

### AWS Secrets Manager

AWS imports use the AWS SDK default credential chain. You can also supply `aws_profile` on the request.

```bash
vault write csv-importer/import/aws/secretsmanager \
  aws_region="us-east-2" \
  secret_id="prod/app/db" \
  kv_mount="secret" \
  destination_path="imports/aws/prod-app-db" \
  parse_json=true \
  include_source_metadata=true
```

If `parse_json=true` and the source secret is a top-level JSON object, each property becomes a KV field. Otherwise the raw value is written under `raw_field`.

### Azure Key Vault

Azure imports use `DefaultAzureCredential`.

```bash
vault write csv-importer/import/azure/keyvault \
  vault_url="https://example-kv.vault.azure.net/" \
  secret_name="prod-app-db" \
  kv_mount="secret" \
  destination_path="imports/azure/prod-app-db" \
  parse_json=false \
  raw_field="secret_value"
```

### CyberArk Conjur

Conjur imports currently use Conjur login plus API key provided on the request.

```bash
vault write csv-importer/import/cyberark/conjur \
  appliance_url="https://conjur.example.com" \
  account="default" \
  login="host/data/prod/app" \
  api_key="..." \
  variable_id="data/prod/app/db-password" \
  kv_mount="secret" \
  destination_path="imports/conjur/db-password" \
  parse_json=false \
  raw_field="value"
```

### Shared Import Behavior

All external imports support these common fields:

- `namespace`
- `kv_mount`
- `destination_path`
- `write_mode`
- `cas`
- `dry_run`
- `parse_json`
- `raw_field`
- `include_source_metadata`

Migration safety notes:

- Duplicate destination paths inside one CSV import are rejected.
- `write_mode="put"` replaces the full KV v2 payload at the destination path.
- `write_mode="patch"` merges fields into the existing secret.
- `cas=0` is the safest create-only option when you do not want to overwrite an existing secret.

## Issues

If you find a bug or want to request an enhancement, open an [issue](https://github.com/andrefaria24/vault-plugin-secrets-importer/issues) in this repository.
