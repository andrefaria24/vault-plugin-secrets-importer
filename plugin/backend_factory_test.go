package plugin

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestFactorySetup(t *testing.T) {
	t.Parallel()

	conf := &logical.BackendConfig{
		StorageView: &logical.InmemStorage{},
		System:      logical.StaticSystemView{},
		Config: map[string]string{
			"plugin_name": "vault-plugin-secrets-importer",
			"plugin_type": "secret",
		},
	}

	b, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatalf("Factory returned error: %v", err)
	}
	if b == nil {
		t.Fatal("expected backend")
	}
}

func TestFactoryHandleConfigWrite(t *testing.T) {
	t.Parallel()

	storage := &logical.InmemStorage{}
	conf := &logical.BackendConfig{
		StorageView: storage,
		System:      logical.StaticSystemView{},
		Config: map[string]string{
			"plugin_name": "vault-plugin-secrets-importer",
			"plugin_type": "secret",
		},
	}

	b, err := Factory(context.Background(), conf)
	if err != nil {
		t.Fatalf("Factory returned error: %v", err)
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"address": "http://127.0.0.1:18200",
			"token":   "hvs.test",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.IsError() {
		t.Fatalf("expected success response, got error response: %#v", resp.Data)
	}
}
