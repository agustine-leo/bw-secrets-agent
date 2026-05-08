package tmpl

import (
	"fmt"
	"strings"
	"testing"

	"github.com/agustine-leo/bw-secrets-agent/internal/config"
)

// fakeSource implements SecretSource backed by static maps.
type fakeSource struct {
	byKey map[string]string
	byID  map[string]string
}

func (f *fakeSource) GetByName(args ...string) (string, error) {
	var lookups []string
	switch len(args) {
	case 1:
		lookups = []string{args[0]}
	case 2:
		lookups = []string{args[0] + "/" + args[1], args[1]}
	default:
		return "", fmt.Errorf("bad arg count")
	}
	for _, k := range lookups {
		if v, ok := f.byKey[k]; ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("not found: %v", args)
}

func (f *fakeSource) GetByID(id string) (string, error) {
	if v, ok := f.byID[id]; ok {
		return v, nil
	}
	return "", fmt.Errorf("not found: %s", id)
}

func newTpl(src string) *config.Template {
	return &config.Template{
		Source:     "test.tpl",
		LeftDelim:  "{{",
		RightDelim: "}}",
	}
}

func TestRender_BareKeyLookup(t *testing.T) {
	r := NewRenderer(&fakeSource{
		byKey: map[string]string{"DB_PASSWORD": "supersecret"},
	})

	got, err := r.Render(newTpl(""), []byte(`pw={{ secret "DB_PASSWORD" }}`))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(got) != "pw=supersecret" {
		t.Errorf("got %q", got)
	}
}

func TestRender_ProjectQualifiedLookup(t *testing.T) {
	r := NewRenderer(&fakeSource{
		byKey: map[string]string{
			"Infra/DB_PASSWORD":      "infra-pw",
			"Production/DB_PASSWORD": "prod-pw",
		},
	})

	got, err := r.Render(newTpl(""), []byte(`{{ secret "Infra" "DB_PASSWORD" }}|{{ secret "Production" "DB_PASSWORD" }}`))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(got) != "infra-pw|prod-pw" {
		t.Errorf("got %q", got)
	}
}

func TestRender_QualifiedFallsBackToBareKey(t *testing.T) {
	r := NewRenderer(&fakeSource{
		byKey: map[string]string{"API_KEY": "ak"},
	})

	got, err := r.Render(newTpl(""), []byte(`{{ secret "Nonexistent" "API_KEY" }}`))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(got) != "ak" {
		t.Errorf("expected fallback to bare key, got %q", got)
	}
}

func TestRender_SecretIDLookup(t *testing.T) {
	r := NewRenderer(&fakeSource{
		byID: map[string]string{"abc-123": "by-id-value"},
	})

	got, err := r.Render(newTpl(""), []byte(`{{ secretID "abc-123" }}`))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(got) != "by-id-value" {
		t.Errorf("got %q", got)
	}
}

func TestRender_MissingSecretIsError(t *testing.T) {
	r := NewRenderer(&fakeSource{byKey: map[string]string{}})

	_, err := r.Render(newTpl(""), []byte(`{{ secret "MISSING" }}`))
	if err == nil {
		t.Fatal("expected error when secret is missing, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestRender_CustomDelimiters(t *testing.T) {
	r := NewRenderer(&fakeSource{
		byKey: map[string]string{"X": "y"},
	})

	tpl := &config.Template{
		Source:     "test.tpl",
		LeftDelim:  "<<",
		RightDelim: ">>",
	}
	got, err := r.Render(tpl, []byte(`a=<< secret "X" >>`))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(got) != "a=y" {
		t.Errorf("got %q", got)
	}
}

func TestRender_InvalidTemplateSyntax(t *testing.T) {
	r := NewRenderer(&fakeSource{})

	_, err := r.Render(newTpl(""), []byte(`{{ this-is-not-valid }`))
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}
