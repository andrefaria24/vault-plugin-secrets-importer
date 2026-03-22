package plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *csvImporterBackend) pathImportCSV() *framework.Path {
	return &framework.Path{
		Pattern: "import/csv",
		Fields: map[string]*framework.FieldSchema{
			"csv": {
				Type:        framework.TypeString,
				Description: "CSV contents. The Vault CLI supports file loading with csv=@/path/to/file.csv.",
			},
			"delimiter": {
				Type:        framework.TypeString,
				Description: "Optional single-character delimiter. Defaults to ','.",
			},
			"namespace": {
				Type:        framework.TypeString,
				Description: "Target Vault namespace for the destination KV v2 mount. Leave empty on Vault Community Edition.",
			},
			"kv_mount": {
				Type:        framework.TypeString,
				Description: "Destination KV v2 mount path.",
			},
			"base_path": {
				Type:        framework.TypeString,
				Description: "Optional prefix prepended to each imported secret path.",
			},
			"path_column": {
				Type:        framework.TypeString,
				Description: "Column containing the relative secret path in per-row mode. Defaults to 'path'.",
			},
			"secret_path": {
				Type:        framework.TypeString,
				Description: "When set, imports the CSV into a single secret path using key_column and value_column.",
			},
			"key_column": {
				Type:        framework.TypeString,
				Description: "Column containing the key in fixed-secret mode. Defaults to 'key'.",
			},
			"value_column": {
				Type:        framework.TypeString,
				Description: "Column containing the value in fixed-secret mode. Defaults to 'value'.",
			},
			"skip_empty_values": {
				Type:        framework.TypeBool,
				Description: "Skip empty CSV values instead of writing empty strings.",
				Default:     true,
			},
			"trim_space": {
				Type:        framework.TypeBool,
				Description: "Trim leading and trailing whitespace from CSV cells and control values.",
				Default:     true,
			},
			"dry_run": {
				Type:        framework.TypeBool,
				Description: "Validate the CSV and return the planned writes without calling Vault.",
				Default:     false,
			},
			"write_mode": {
				Type:        framework.TypeString,
				Description: "KV v2 write mode: 'put' to replace the secret data or 'patch' to merge fields into an existing secret.",
				Default:     writeModePut,
			},
			"cas": {
				Type:        framework.TypeInt,
				Description: "Optional KV v2 check-and-set value. Use 0 to create only when the secret does not exist; use a positive value to require a specific current version; omit or set -1 to disable CAS.",
				Default:     -1,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathImportCSVWrite,
			logical.UpdateOperation: b.pathImportCSVWrite,
		},
		ExistenceCheck: alwaysNotFoundExistenceCheck,
		HelpSynopsis:    "Import CSV data into an existing KV v2 mount.",
		HelpDescription: pathImportCSVHelp,
	}
}

func (b *csvImporterBackend) pathImportCSVWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	csvPayload := strings.TrimSpace(data.Get("csv").(string))
	if csvPayload == "" {
		return logical.ErrorResponse("csv is required"), nil
	}

	kvMount := strings.Trim(strings.TrimSpace(data.Get("kv_mount").(string)), "/")
	if kvMount == "" {
		return logical.ErrorResponse("kv_mount is required"), nil
	}

	importReq := csvImportRequest{
		CSV:             csvPayload,
		Delimiter:       data.Get("delimiter").(string),
		BasePath:        data.Get("base_path").(string),
		PathColumn:      data.Get("path_column").(string),
		SecretPath:      data.Get("secret_path").(string),
		KeyColumn:       data.Get("key_column").(string),
		ValueColumn:     data.Get("value_column").(string),
		SkipEmptyValues: data.Get("skip_empty_values").(bool),
		TrimSpace:       data.Get("trim_space").(bool),
	}

	result, err := buildWritesFromCSV(importReq)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	writeMode := normalizeWriteMode(data.Get("write_mode").(string))
	if writeMode == "" {
		return logical.ErrorResponse("write_mode must be one of: put, patch"), nil
	}
	cas := data.Get("cas").(int)
	if cas < -1 {
		return logical.ErrorResponse("cas must be -1, 0, or a positive version number"), nil
	}

	paths := make([]string, 0, len(result.Writes))
	totalFields := 0
	for _, write := range result.Writes {
		paths = append(paths, write.Path)
		totalFields += len(write.Data)
	}

	dryRun := data.Get("dry_run").(bool)
	namespace := cleanNamespace(data.Get("namespace").(string))
	if !dryRun {
		cfg, err := loadConnectionConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if cfg == nil {
			return logical.ErrorResponse("plugin config is missing; write to config before importing"), nil
		}

		writer, err := b.writerFactory(cfg)
		if err != nil {
			return nil, err
		}

		for _, write := range result.Writes {
			if err := writer.WriteSecret(ctx, vaultWriteRequest{
				Namespace: namespace,
				Mount:     kvMount,
				Path:      write.Path,
				Data:      write.Data,
				WriteMode: writeMode,
				CAS:       cas,
			}); err != nil {
				return nil, fmt.Errorf("import path %q: %w", write.Path, err)
			}
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"mode":             string(result.Mode),
			"namespace":        namespace,
			"kv_mount":         kvMount,
			"base_path":        strings.Trim(strings.TrimSpace(importReq.BasePath), "/"),
			"dry_run":          dryRun,
			"write_mode":       writeMode,
			"cas":              cas,
			"csv_rows":         result.TotalRows,
			"imported_secrets": len(result.Writes),
			"imported_fields":  totalFields,
			"paths":            paths,
		},
	}, nil
}

const pathImportCSVHelp = `
CSV import supports two modes:

1. Per-row secret mode:
   The CSV must include a path column. Every non-path column becomes a field on the secret.

2. Fixed-secret mode:
   Set secret_path and provide key/value columns. Every CSV row becomes one field inside the same secret.
`
