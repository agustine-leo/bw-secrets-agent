// Package tmpl renders Go text/template files with three Bitwarden helpers:
// `secret PROJECT KEY`, `secret KEY`, and `secretID UUID`.
package tmpl

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/agustine-leo/bw-secrets-agent/internal/bwclient"
	"github.com/agustine-leo/bw-secrets-agent/internal/config"
)

// Renderer renders Go templates with Bitwarden SM secrets injected via
// the secret() and secretID() template functions.
type Renderer struct {
	client *bwclient.Client
}

func NewRenderer(client *bwclient.Client) *Renderer {
	return &Renderer{client: client}
}

// Render executes the template source against the cached secret store.
func (r *Renderer) Render(tpl *config.Template, source []byte) ([]byte, error) {
	funcMap := template.FuncMap{
		// secret "key"            → lookup by bare key
		// secret "project" "key" → lookup by project + key
		"secret": func(args ...string) (string, error) {
			return r.client.GetByName(args...)
		},
		// secretID "uuid" → lookup by Bitwarden secret UUID
		"secretID": func(id string) (string, error) {
			return r.client.GetByID(id)
		},
	}

	t, err := template.New("").
		Delims(tpl.LeftDelim, tpl.RightDelim).
		Option("missingkey=error").
		Funcs(funcMap).
		Parse(string(source))
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, nil); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}
	return buf.Bytes(), nil
}
