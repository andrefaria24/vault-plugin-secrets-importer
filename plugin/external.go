package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const defaultRawField = "value"

type externalImportRequest struct {
	Namespace     string
	KVMount       string
	Destination   string
	WriteMode     string
	CAS           int
	ParseJSON     bool
	RawField      string
	IncludeSource bool
}

type externalSecret struct {
	SourceType string
	SourceID   string
	Version    string
	Data       map[string]interface{}
	Metadata   map[string]interface{}
}

func sharedImportFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"namespace": {
			Type:        framework.TypeString,
			Description: "Target Vault namespace for the destination KV v2 mount. Leave empty on Vault Community Edition.",
		},
		"kv_mount": {
			Type:        framework.TypeString,
			Description: "Destination KV v2 mount path.",
		},
		"destination_path": {
			Type:        framework.TypeString,
			Description: "Destination secret path inside the KV v2 mount.",
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
		"parse_json": {
			Type:        framework.TypeBool,
			Description: "When true, parse the source secret as a JSON object and import each top-level property as a KV field.",
			Default:     true,
		},
		"raw_field": {
			Type:        framework.TypeString,
			Description: "Field name used when parse_json=false or the source secret is not structured JSON. Defaults to 'value'.",
			Default:     defaultRawField,
		},
		"include_source_metadata": {
			Type:        framework.TypeBool,
			Description: "When true, include selected source metadata under the _source field in the stored Vault secret.",
			Default:     false,
		},
		"dry_run": {
			Type:        framework.TypeBool,
			Description: "Validate and preview the import without writing to Vault.",
			Default:     false,
		},
	}
}

func readExternalImportRequest(data *framework.FieldData) (*externalImportRequest, *logical.Response) {
	kvMount := strings.Trim(strings.TrimSpace(data.Get("kv_mount").(string)), "/")
	if kvMount == "" {
		return nil, logical.ErrorResponse("kv_mount is required")
	}

	destination := strings.Trim(strings.TrimSpace(data.Get("destination_path").(string)), "/")
	if destination == "" {
		return nil, logical.ErrorResponse("destination_path is required")
	}

	writeMode := normalizeWriteMode(data.Get("write_mode").(string))
	if writeMode == "" {
		return nil, logical.ErrorResponse("write_mode must be one of: put, patch")
	}

	cas := data.Get("cas").(int)
	if cas < -1 {
		return nil, logical.ErrorResponse("cas must be -1, 0, or a positive version number")
	}

	rawField := defaultString(data.Get("raw_field").(string), defaultRawField)
	if strings.TrimSpace(rawField) == "" {
		return nil, logical.ErrorResponse("raw_field must not be empty")
	}

	return &externalImportRequest{
		Namespace:     cleanNamespace(data.Get("namespace").(string)),
		KVMount:       kvMount,
		Destination:   destination,
		WriteMode:     writeMode,
		CAS:           cas,
		ParseJSON:     data.Get("parse_json").(bool),
		RawField:      rawField,
		IncludeSource: data.Get("include_source_metadata").(bool),
	}, nil
}

func normalizeExternalSecret(rawString string, rawBinary []byte, parseJSON bool, rawField string) (map[string]interface{}, error) {
	if rawString == "" && len(rawBinary) == 0 {
		return nil, fmt.Errorf("source secret did not contain a value")
	}

	if rawString != "" {
		if parseJSON {
			var payload map[string]interface{}
			if err := json.Unmarshal([]byte(rawString), &payload); err == nil {
				if len(payload) == 0 {
					return nil, fmt.Errorf("source secret JSON object was empty")
				}
				return payload, nil
			}
		}

		return map[string]interface{}{
			rawField: rawString,
		}, nil
	}

	return map[string]interface{}{
		rawField: base64.StdEncoding.EncodeToString(rawBinary),
	}, nil
}

func (b *csvImporterBackend) importExternalSecret(ctx context.Context, req *logical.Request, importReq *externalImportRequest, secret *externalSecret, dryRun bool) (*logical.Response, error) {
	if secret == nil {
		return nil, fmt.Errorf("source secret was nil")
	}

	data := make(map[string]interface{}, len(secret.Data)+1)
	for k, v := range secret.Data {
		data[k] = v
	}
	if importReq.IncludeSource && len(secret.Metadata) > 0 {
		data["_source"] = secret.Metadata
	}

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

		if err := writer.WriteSecret(ctx, vaultWriteRequest{
			Namespace: importReq.Namespace,
			Mount:     importReq.KVMount,
			Path:      importReq.Destination,
			Data:      data,
			WriteMode: importReq.WriteMode,
			CAS:       importReq.CAS,
		}); err != nil {
			return nil, fmt.Errorf("import path %q: %w", importReq.Destination, err)
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"source_type":       secret.SourceType,
			"source_id":         secret.SourceID,
			"source_version":    secret.Version,
			"namespace":         importReq.Namespace,
			"kv_mount":          importReq.KVMount,
			"destination_path":  importReq.Destination,
			"write_mode":        importReq.WriteMode,
			"cas":               importReq.CAS,
			"dry_run":           dryRun,
			"imported_fields":   len(data),
			"included_metadata": importReq.IncludeSource,
		},
	}, nil
}
