package plugin

import "testing"

func TestNormalizeExternalSecretParsesJSONObject(t *testing.T) {
	data, err := normalizeExternalSecret(`{"username":"svc-user","password":"s3cr3t"}`, nil, true, defaultRawField)
	if err != nil {
		t.Fatalf("normalizeExternalSecret returned error: %v", err)
	}
	if got, want := data["username"], "svc-user"; got != want {
		t.Fatalf("username mismatch: got %v want %v", got, want)
	}
	if got, want := len(data), 2; got != want {
		t.Fatalf("field count mismatch: got %d want %d", got, want)
	}
}

func TestNormalizeExternalSecretFallsBackToRawField(t *testing.T) {
	data, err := normalizeExternalSecret("plain-text-secret", nil, false, "secret_value")
	if err != nil {
		t.Fatalf("normalizeExternalSecret returned error: %v", err)
	}
	if got, want := data["secret_value"], "plain-text-secret"; got != want {
		t.Fatalf("raw field mismatch: got %v want %v", got, want)
	}
}
