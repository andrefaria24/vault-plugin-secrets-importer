package plugin

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

type vaultConnectionConfig struct {
	Address       string `json:"address"`
	Token         string `json:"token,omitempty"`
	TokenFile     string `json:"token_file,omitempty"`
	CACert        string `json:"ca_cert,omitempty"`
	CACertFile    string `json:"ca_cert_file,omitempty"`
	CAPath        string `json:"ca_path,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
	DefaultNS     string `json:"default_namespace,omitempty"`
}

type vaultWriteRequest struct {
	Namespace string
	Mount     string
	Path      string
	Data      map[string]interface{}
	WriteMode string
	CAS       int
}

type vaultWriter interface {
	WriteSecret(context.Context, vaultWriteRequest) error
	CheckConnection(context.Context, string) (map[string]interface{}, error)
}

type httpVaultWriter struct {
	address   string
	token     string
	tokenFile string
	defaultNS string
	tlsConfig *api.TLSConfig
}

func newVaultWriter(cfg *vaultConnectionConfig) (vaultWriter, error) {
	if cfg == nil {
		return nil, fmt.Errorf("plugin configuration is missing")
	}

	address := strings.TrimSpace(cfg.Address)
	if address == "" {
		return nil, fmt.Errorf("config.address is required")
	}

	if strings.TrimSpace(cfg.Token) == "" && strings.TrimSpace(cfg.TokenFile) == "" {
		return nil, fmt.Errorf("one of config.token or config.token_file must be set")
	}

	writer := &httpVaultWriter{
		address:   address,
		token:     strings.TrimSpace(cfg.Token),
		tokenFile: strings.TrimSpace(cfg.TokenFile),
		defaultNS: cleanNamespace(cfg.DefaultNS),
	}

	if cfg.CACert != "" || cfg.CACertFile != "" || cfg.CAPath != "" || cfg.TLSServerName != "" || cfg.TLSSkipVerify {
		writer.tlsConfig = &api.TLSConfig{
			CACert:        strings.TrimSpace(cfg.CACertFile),
			CACertBytes:   []byte(cfg.CACert),
			CAPath:        strings.TrimSpace(cfg.CAPath),
			TLSServerName: strings.TrimSpace(cfg.TLSServerName),
			Insecure:      cfg.TLSSkipVerify,
		}
	}

	return writer, nil
}

func (w *httpVaultWriter) WriteSecret(ctx context.Context, req vaultWriteRequest) error {
	client, err := w.clientForNamespace(req.Namespace)
	if err != nil {
		return err
	}

	kv := client.KVv2(req.Mount)
	mode := normalizeWriteMode(req.WriteMode)
	switch mode {
	case writeModePatch:
		opts := make([]api.KVOption, 0, 2)
		opts = append(opts, api.WithMergeMethod("rw"))
		if req.CAS >= 0 {
			opts = append(opts, api.WithCheckAndSet(req.CAS))
		}
		if _, err := kv.Patch(ctx, req.Path, req.Data, opts...); err != nil {
			return fmt.Errorf("patch %s/%s failed: %w", req.Mount, req.Path, err)
		}
	default:
		opts := make([]api.KVOption, 0, 1)
		if req.CAS >= 0 {
			opts = append(opts, api.WithCheckAndSet(req.CAS))
		}
		if _, err := kv.Put(ctx, req.Path, req.Data, opts...); err != nil {
			return fmt.Errorf("write to %s/%s failed: %w", req.Mount, req.Path, err)
		}
	}

	return nil
}

func (w *httpVaultWriter) clientForNamespace(namespace string) (*api.Client, error) {
	cfg := api.DefaultConfig()
	cfg.Address = w.address

	if w.tlsConfig != nil {
		if err := cfg.ConfigureTLS(w.tlsConfig); err != nil {
			return nil, fmt.Errorf("configure Vault TLS client: %w", err)
		}
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create Vault API client: %w", err)
	}

	token, err := w.resolveToken()
	if err != nil {
		return nil, err
	}
	client.SetToken(token)

	targetNS := cleanNamespace(namespace)
	if targetNS == "" {
		targetNS = w.defaultNS
	}
	if targetNS != "" {
		client.SetNamespace(targetNS)
	}

	return client, nil
}

func (w *httpVaultWriter) CheckConnection(ctx context.Context, namespace string) (map[string]interface{}, error) {
	client, err := w.clientForNamespace(namespace)
	if err != nil {
		return nil, err
	}

	_ = ctx

	health, err := client.Sys().Health()
	if err != nil {
		return nil, fmt.Errorf("read Vault health: %w", err)
	}
	if _, err := client.Auth().Token().LookupSelf(); err != nil {
		return nil, fmt.Errorf("lookup configured token: %w", err)
	}

	targetNS := cleanNamespace(namespace)
	if targetNS == "" {
		targetNS = w.defaultNS
	}

	return map[string]interface{}{
		"address":      w.address,
		"namespace":    targetNS,
		"version":      health.Version,
		"cluster_name": health.ClusterName,
		"initialized":  health.Initialized,
		"sealed":       health.Sealed,
		"standby":      health.Standby,
		"token_lookup": true,
	}, nil
}

func (w *httpVaultWriter) resolveToken() (string, error) {
	if w.token != "" {
		return w.token, nil
	}

	raw, err := os.ReadFile(w.tokenFile)
	if err != nil {
		return "", fmt.Errorf("read config.token_file: %w", err)
	}

	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("config.token_file did not contain a token")
	}

	return token, nil
}
