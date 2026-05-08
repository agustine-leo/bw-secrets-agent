package agent

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func TestResolveUID_Numeric(t *testing.T) {
	got, err := resolveUID("1234")
	if err != nil {
		t.Fatalf("numeric: %v", err)
	}
	if got != 1234 {
		t.Errorf("want 1234, got %d", got)
	}
}

func TestResolveUID_Name(t *testing.T) {
	// Use the current process's own username — guaranteed to exist.
	cur, err := user.Current()
	if err != nil {
		t.Skipf("cannot read current user: %v", err)
	}
	got, err := resolveUID(cur.Username)
	if err != nil {
		t.Fatalf("by name: %v", err)
	}
	wantUID, _ := strconv.Atoi(cur.Uid)
	if got != wantUID {
		t.Errorf("want %d, got %d", wantUID, got)
	}
}

func TestResolveUID_Unknown(t *testing.T) {
	if _, err := resolveUID("definitely-not-a-real-user-name-xyz123"); err == nil {
		t.Error("expected error for unknown user, got nil")
	}
}

func TestResolveGID_Numeric(t *testing.T) {
	got, err := resolveGID("321")
	if err != nil {
		t.Fatalf("numeric: %v", err)
	}
	if got != 321 {
		t.Errorf("want 321, got %d", got)
	}
}

// TestChownFile_NoOp verifies that passing both empty strings is fine
// (the agent skips the call entirely in renderTemplate, but the helper
// itself should accept "preserve UID, preserve GID" as a valid request).
func TestChownFile_NoOp(t *testing.T) {
	// Write a temp file we own so chown(-1, -1) is a guaranteed no-op even
	// without privileges.
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := chownFile(path, "", ""); err != nil {
		t.Fatalf("no-op chown should succeed: %v", err)
	}
}

func TestChownFile_UnknownUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	os.WriteFile(path, []byte("x"), 0o600)

	err := chownFile(path, "definitely-not-a-real-user-name-xyz123", "")
	if err == nil {
		t.Error("expected error for unknown user, got nil")
	}
}
