package plugin

import "testing"

func TestBuildWritesFromCSVRowMode(t *testing.T) {
	result, err := buildWritesFromCSV(csvImportRequest{
		CSV:             "path,username,password\napps/dev/db,svc-user,s3cr3t\napps/dev/api,api-user,topsecret\n",
		BasePath:        "team-a",
		SkipEmptyValues: true,
		TrimSpace:       true,
	})
	if err != nil {
		t.Fatalf("buildWritesFromCSV returned error: %v", err)
	}

	if got, want := string(result.Mode), string(csvImportModeRow); got != want {
		t.Fatalf("mode mismatch: got %q want %q", got, want)
	}
	if got, want := len(result.Writes), 2; got != want {
		t.Fatalf("write count mismatch: got %d want %d", got, want)
	}
	if got, want := result.Writes[0].Path, "team-a/apps/dev/db"; got != want {
		t.Fatalf("first path mismatch: got %q want %q", got, want)
	}
	if got, want := result.Writes[0].Data["username"], "svc-user"; got != want {
		t.Fatalf("username mismatch: got %v want %v", got, want)
	}
}

func TestBuildWritesFromCSVFixedSecretMode(t *testing.T) {
	result, err := buildWritesFromCSV(csvImportRequest{
		CSV:             "key,value\nusername,svc-user\npassword,s3cr3t\n",
		BasePath:        "apps/dev",
		SecretPath:      "db",
		SkipEmptyValues: true,
		TrimSpace:       true,
	})
	if err != nil {
		t.Fatalf("buildWritesFromCSV returned error: %v", err)
	}

	if got, want := string(result.Mode), string(csvImportModeKV); got != want {
		t.Fatalf("mode mismatch: got %q want %q", got, want)
	}
	if got, want := len(result.Writes), 1; got != want {
		t.Fatalf("write count mismatch: got %d want %d", got, want)
	}
	if got, want := result.Writes[0].Path, "apps/dev/db"; got != want {
		t.Fatalf("path mismatch: got %q want %q", got, want)
	}
	if got, want := result.Writes[0].Data["password"], "s3cr3t"; got != want {
		t.Fatalf("password mismatch: got %v want %v", got, want)
	}
}

func TestBuildWritesFromCSVRequiresPathColumn(t *testing.T) {
	_, err := buildWritesFromCSV(csvImportRequest{
		CSV:             "username,password\nsvc-user,s3cr3t\n",
		SkipEmptyValues: true,
		TrimSpace:       true,
	})
	if err == nil {
		t.Fatal("expected missing path column error")
	}
}

func TestBuildWritesFromCSVDuplicatePathFails(t *testing.T) {
	_, err := buildWritesFromCSV(csvImportRequest{
		CSV:             "path,username\napps/dev/db,svc-user\napps/dev/db,svc-user-2\n",
		SkipEmptyValues: true,
		TrimSpace:       true,
	})
	if err == nil {
		t.Fatal("expected duplicate path error")
	}
}
