// Package bwclient implements a Bitwarden Secrets Manager client that speaks
// directly to the Bitwarden identity + API endpoints — no bws binary required.
//
// Auth flow (mirrors what the official SDK does internally):
//  1. Parse the machine-account access token string.
//  2. OAuth2 client_credentials exchange → JWT + encrypted_payload.
//  3. Decrypt encrypted_payload (AES-256-CBC+HMAC) → org symmetric key.
//  4. List secrets/projects via the API (Bearer JWT).
//  5. Decrypt every secret key/value with the org key.
package bwclient

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultIdentityURL = "https://identity.bitwarden.com"
	defaultAPIURL      = "https://api.bitwarden.com"
)

// ── Access token parsing ──────────────────────────────────────────────────────
//
// Format v0: "0.{tokenId}.{clientSecret}:{encKey64}"
// Format v1: "1.{tokenId}.{clientSecret}:{encKey64}:{base64(serverURL)}"

type parsedToken struct {
	AccessTokenID string
	ClientSecret  string
	EncryptionKey []byte // 64 bytes: [0:32]=AES, [32:64]=HMAC
	ServerURL     string // empty for cloud
}

func parseAccessToken(s string) (*parsedToken, error) {
	dotIdx := strings.Index(s, ".")
	if dotIdx < 0 {
		return nil, fmt.Errorf("missing version separator ('.')")
	}
	version := s[:dotIdx]
	rest := s[dotIdx+1:]

	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("missing ':' separator between client secret and encryption key")
	}
	tokenPart := rest[:colonIdx]  // "{tokenId}.{clientSecret}"
	afterColon := rest[colonIdx+1:]

	lastDot := strings.LastIndex(tokenPart, ".")
	if lastDot < 0 {
		return nil, fmt.Errorf("missing '.' separator between token ID and client secret")
	}

	tok := &parsedToken{
		AccessTokenID: tokenPart[:lastDot],
		ClientSecret:  tokenPart[lastDot+1:],
	}

	var encKeyStr string
	switch version {
	case "0":
		encKeyStr = afterColon
	case "1":
		// afterColon = "{encKey}:{base64serverURL}"
		ci := strings.LastIndex(afterColon, ":")
		if ci < 0 {
			return nil, fmt.Errorf("v1 token: missing server URL separator")
		}
		encKeyStr = afterColon[:ci]
		urlBytes, err := b64Decode(afterColon[ci+1:])
		if err != nil {
			return nil, fmt.Errorf("v1 token: invalid server URL encoding: %w", err)
		}
		tok.ServerURL = string(urlBytes)
	default:
		return nil, fmt.Errorf("unsupported access token version %q", version)
	}

	raw, err := b64Decode(encKeyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key: %w", err)
	}
	// BWS machine-account tokens carry a 16-byte seed; the actual working
	// key is derived through derive_shareable_key (custom Extract + HKDF).
	if len(raw) != 16 {
		return nil, fmt.Errorf("expected 16-byte access-token seed, got %d bytes", len(raw))
	}
	derived, err := deriveAccessTokenKey(raw)
	if err != nil {
		return nil, fmt.Errorf("deriving access-token key: %w", err)
	}
	tok.EncryptionKey = derived
	return tok, nil
}

// deriveShareableKey is Bitwarden's `derive_shareable_key(secret, name, info)`
// (see bitwarden-crypto/src/keys/shareable_key.rs). It derives a 64-byte
// AES-256-CBC + HMAC-SHA256 working key from a 16-byte seed:
//
//	prk = HMAC-SHA256(key="bitwarden-"+name, msg=seed)
//	okm = HKDF-Expand(prk, info, L=64)
//
// `info` may be empty, matching the `Option::None` branch in the Rust source.
func deriveShareableKey(seed []byte, name, info string) ([]byte, error) {
	h := hmac.New(sha256.New, []byte("bitwarden-"+name))
	h.Write(seed)
	prk := h.Sum(nil)
	return hkdf.Expand(sha256.New, prk, info, 64)
}

// deriveAccessTokenKey is the BWS-specific specialization used to unwrap
// the identity server's `encrypted_payload`.
func deriveAccessTokenKey(seed []byte) ([]byte, error) {
	return deriveShareableKey(seed, "accesstoken", "sm-access-token")
}

// ── Bitwarden EncString crypto ───────────────────────────────────────────────
//
// EncString format (type 2): "2.{b64iv}|{b64ct}|{b64mac}"
// The type prefix and its dot may be omitted in some contexts.

func decryptEncString(s string, key []byte) ([]byte, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("key must be at least 32 bytes, got %d", len(key))
	}
	// Strip optional "N." type prefix (e.g. "2.").
	if dot := strings.Index(s, "."); dot >= 0 && dot <= 1 {
		s = s[dot+1:]
	}
	parts := strings.SplitN(s, "|", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 '|'-separated parts, got %d", len(parts))
	}
	iv, err := b64Decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("IV: %w", err)
	}
	ct, err := b64Decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ciphertext: %w", err)
	}
	mac, err := b64Decode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("MAC: %w", err)
	}

	aesKey, macKey := key[:32], key[32:]

	// Verify HMAC-SHA256(macKey, IV || CT).
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ct)
	if !hmac.Equal(h.Sum(nil), mac) {
		return nil, fmt.Errorf("HMAC-SHA256 verification failed (wrong key or corrupted data)")
	}

	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is invalid (must be non-zero and a multiple of %d)", len(ct), aes.BlockSize)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	return pkcs7Unpad(plain)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(b) {
		return nil, fmt.Errorf("invalid PKCS#7 padding byte: %d", pad)
	}
	for _, v := range b[len(b)-pad:] {
		if int(v) != pad {
			return nil, fmt.Errorf("inconsistent PKCS#7 padding")
		}
	}
	return b[:len(b)-pad], nil
}

// b64Decode tries all standard base64 variants (std/url × padded/raw).
func b64Decode(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("cannot base64-decode %q", s)
}

// ── JWT org-ID extraction ────────────────────────────────────────────────────

func orgIDFromJWT(jwtStr string) string {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	for _, name := range []string{"organization", "organizationId", "org_id"} {
		if v, ok := claims[name]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil && s != "" {
				return s
			}
		}
	}
	return ""
}

// ── Client ───────────────────────────────────────────────────────────────────

// Client authenticates against Bitwarden Secrets Manager and caches
// decrypted secrets in memory. All methods are safe for concurrent use.
type Client struct {
	rawToken    string
	identityURL string
	apiURL      string
	httpClient  *http.Client

	// Auth state — protected by authMu.
	authMu      sync.Mutex
	jwt         string
	orgID       string
	orgKey      []byte // 64-byte symmetric key for decrypting secrets
	tokenExpiry time.Time

	// Decrypted secret cache — replaced atomically on each Refresh.
	cacheMu sync.RWMutex
	byID    map[string]string // secret UUID → plaintext value
	byKey   map[string]string // "project/key" and "key" → plaintext value
}

func New(accessToken, serverURL string) *Client {
	iURL, aURL := defaultIdentityURL, defaultAPIURL
	if serverURL != "" {
		base := strings.TrimRight(serverURL, "/")
		iURL = base + "/identity"
		aURL = base + "/api"
	}
	return &Client{
		rawToken:    accessToken,
		identityURL: iURL,
		apiURL:      aURL,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		byID:        make(map[string]string),
		byKey:       make(map[string]string),
	}
}

func (c *Client) AccessToken() string { return c.rawToken }

// Refresh (re-)authenticates if needed, then fetches and decrypts all secrets.
func (c *Client) Refresh(ctx context.Context) error {
	if err := c.ensureAuth(ctx); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	return c.fetchAndCache(ctx)
}

// ── Authentication ───────────────────────────────────────────────────────────

func (c *Client) ensureAuth(ctx context.Context) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	// Renew 60 s before expiry to avoid mid-cycle token expiry.
	if c.jwt != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return nil
	}
	return c.login(ctx)
}

func (c *Client) login(ctx context.Context) error {
	pt, err := parseAccessToken(c.rawToken)
	if err != nil {
		return fmt.Errorf("parsing access token: %w", err)
	}
	if pt.ServerURL != "" {
		base := strings.TrimRight(pt.ServerURL, "/")
		c.identityURL = base + "/identity"
		c.apiURL = base + "/api"
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"scope":         {"api.secrets"},
		"client_id":     {pt.AccessTokenID},
		"client_secret": {pt.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.identityURL+"/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST /connect/token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("identity server returned HTTP %d: %s", resp.StatusCode, truncate(body, 300))
	}

	var tr struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int    `json:"expires_in"`
		EncryptedPayload string `json:"encrypted_payload"`
		// Included in some server versions.
		OrganizationID string `json:"organizationId"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("parsing token response: %w", err)
	}
	if tr.AccessToken == "" {
		return fmt.Errorf("token response missing access_token field")
	}
	if tr.EncryptedPayload == "" {
		return fmt.Errorf("token response missing encrypted_payload field")
	}

	orgKey, orgID, err := resolveOrgKeyAndID(tr.EncryptedPayload, tr.OrganizationID, tr.AccessToken, pt.EncryptionKey)
	if err != nil {
		return fmt.Errorf("resolving org key: %w", err)
	}

	c.jwt = tr.AccessToken
	c.orgID = orgID
	c.orgKey = orgKey
	expiry := 3600
	if tr.ExpiresIn > 0 {
		expiry = tr.ExpiresIn
	}
	c.tokenExpiry = time.Now().Add(time.Duration(expiry) * time.Second)

	slog.Debug("authenticated to Bitwarden SM", "orgID", orgID, "expiresIn", expiry)
	return nil
}

// resolveOrgKeyAndID handles two payload variants seen in the wild:
//
//  1. JSON payload: {"organizationId":"…","encryptionKey":"<encString>"}
//     The inner encString is decrypted with the same access-token key.
//
//  2. Raw payload: the decrypted bytes are the 64-byte org key directly.
//
// The org ID is sourced from (in order): payload JSON → top-level token field
// → JWT claims.
func resolveOrgKeyAndID(encPayload, topLevelOrgID, jwtStr string, tokenKey []byte) (orgKey []byte, orgID string, err error) {
	raw, err := decryptEncString(encPayload, tokenKey)
	if err != nil {
		return nil, "", fmt.Errorf("decrypting payload: %w", err)
	}

	// Try JSON path first.
	var payload struct {
		OrganizationID string `json:"organizationId"`
		EncryptionKey  string `json:"encryptionKey"`
	}
	if jerr := json.Unmarshal(raw, &payload); jerr == nil && payload.EncryptionKey != "" {
		if strings.Contains(payload.EncryptionKey, "|") {
			// Inner EncString — decrypt with the same token key.
			orgKey, err = decryptEncString(payload.EncryptionKey, tokenKey)
		} else {
			// Raw base64 key.
			orgKey, err = b64Decode(payload.EncryptionKey)
		}
		if err != nil {
			return nil, "", fmt.Errorf("extracting org key from JSON payload: %w", err)
		}
		orgID = payload.OrganizationID
	} else if len(raw) == 64 {
		// Raw-bytes path.
		orgKey = raw
	} else {
		return nil, "", fmt.Errorf("unexpected decrypted payload: %d bytes, json-parse: %v", len(raw), jerr)
	}

	if len(orgKey) != 64 {
		return nil, "", fmt.Errorf("org key must be 64 bytes, got %d", len(orgKey))
	}

	// Resolve org ID from best available source.
	if orgID == "" {
		orgID = topLevelOrgID
	}
	if orgID == "" {
		orgID = orgIDFromJWT(jwtStr)
	}
	if orgID == "" {
		return nil, "", fmt.Errorf("organization ID not found in token response or JWT claims")
	}
	return orgKey, orgID, nil
}

// ── Secret fetching ──────────────────────────────────────────────────────────

// apiProjectRef is the project metadata embedded inside each secret.
// `name` is an EncString (encrypted with the org key).
type apiProjectRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// apiSecretRef is the metadata-only entry returned by the list endpoint.
type apiSecretRef struct {
	ID       string          `json:"id"`
	Key      string          `json:"key"` // EncString
	Projects []apiProjectRef `json:"projects"`
}

// apiSecret is the full secret returned by GET /secrets/{id} or the bulk endpoint.
type apiSecret struct {
	ID       string          `json:"id"`
	Key      string          `json:"key"`   // EncString
	Value    string          `json:"value"` // EncString
	Note     string          `json:"note"`  // EncString
	Projects []apiProjectRef `json:"projects"`
}

func (c *Client) fetchAndCache(ctx context.Context) error {
	c.authMu.Lock()
	jwt, orgID, orgKey := c.jwt, c.orgID, c.orgKey
	c.authMu.Unlock()

	// Step 1: list secrets to discover IDs (no values returned).
	refs, err := c.listSecrets(ctx, jwt, orgID)
	if err != nil {
		return fmt.Errorf("listing secrets: %w", err)
	}
	if len(refs) == 0 {
		c.cacheMu.Lock()
		c.byID = map[string]string{}
		c.byKey = map[string]string{}
		c.cacheMu.Unlock()
		slog.Info("no secrets accessible to this access token")
		return nil
	}

	// Step 2: bulk-fetch values for all IDs.
	ids := make([]string, len(refs))
	for i, r := range refs {
		ids[i] = r.ID
	}
	secrets, err := c.getSecretsByIDs(ctx, jwt, ids)
	if err != nil {
		return fmt.Errorf("fetching secret values: %w", err)
	}

	// Step 3: decrypt and build lookup maps.
	byID := make(map[string]string, len(secrets))
	byKey := make(map[string]string, len(secrets)*2)
	projNameCache := make(map[string]string)

	for _, s := range secrets {
		key, err := decryptString(s.Key, orgKey)
		if err != nil {
			slog.Warn("cannot decrypt secret key", "id", s.ID, "err", err)
			continue
		}
		val, err := decryptString(s.Value, orgKey)
		if err != nil {
			slog.Warn("cannot decrypt secret value", "id", s.ID, "err", err)
			continue
		}

		byID[s.ID] = val
		if _, dup := byKey[key]; dup {
			// Don't log the key name — it's sensitive metadata.
			// Operators can disambiguate with project-qualified template lookups.
			slog.Warn("duplicate secret key across projects — bare-key lookups return last seen value; use project-qualified form to disambiguate")
		}
		byKey[key] = val

		// Each secret carries its project's encrypted name; decrypt once and cache.
		for _, p := range s.Projects {
			pName, ok := projNameCache[p.ID]
			if !ok {
				decoded, err := decryptString(p.Name, orgKey)
				if err != nil {
					slog.Warn("cannot decrypt project name", "id", p.ID, "err", err)
					continue
				}
				projNameCache[p.ID] = decoded
				pName = decoded
			}
			byKey[pName+"/"+key] = val
		}
	}

	c.cacheMu.Lock()
	c.byID = byID
	c.byKey = byKey
	c.cacheMu.Unlock()

	slog.Info("secrets refreshed", "count", len(byID), "projects", len(projNameCache))
	return nil
}

func decryptString(enc string, key []byte) (string, error) {
	b, err := decryptEncString(enc, key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// listSecrets calls GET /organizations/{orgId}/secrets and returns
// metadata-only refs. The response wraps the array under "secrets".
func (c *Client) listSecrets(ctx context.Context, jwt, orgID string) ([]apiSecretRef, error) {
	var body struct {
		Secrets []apiSecretRef `json:"secrets"`
	}
	if err := c.apiGet(ctx, jwt, "/organizations/"+orgID+"/secrets", &body); err != nil {
		return nil, err
	}
	return body.Secrets, nil
}

// getSecretsByIDs calls POST /secrets/get-by-ids and returns full secrets
// (with decryptable key/value/note). The response wraps the array under "data".
func (c *Client) getSecretsByIDs(ctx context.Context, jwt string, ids []string) ([]apiSecret, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var body struct {
		Data []apiSecret `json:"data"`
	}
	if err := c.apiPost(ctx, jwt, "/secrets/get-by-ids", map[string]any{"ids": ids}, &body); err != nil {
		return nil, err
	}
	return body.Data, nil
}

func (c *Client) apiGet(ctx context.Context, jwt, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned HTTP %d: %s", path, resp.StatusCode, truncate(body, 300))
	}
	return json.Unmarshal(body, out)
}

func (c *Client) apiPost(ctx context.Context, jwt, path string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s returned HTTP %d: %s", path, resp.StatusCode, truncate(respBody, 300))
	}
	return json.Unmarshal(respBody, out)
}

// ── Lookup ───────────────────────────────────────────────────────────────────

// GetByName resolves a secret value from the in-memory cache.
//
//	GetByName("key")             → bare-key lookup
//	GetByName("project", "key") → "project/key" lookup, falls back to bare key
func (c *Client) GetByName(args ...string) (string, error) {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	var candidates []string
	switch len(args) {
	case 1:
		candidates = []string{args[0]}
	case 2:
		candidates = []string{args[0] + "/" + args[1], args[1]}
	default:
		return "", fmt.Errorf("secret() takes 1 or 2 arguments, got %d", len(args))
	}
	for _, k := range candidates {
		if v, ok := c.byKey[k]; ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("secret %q not found in cache", strings.Join(args, "/"))
}

// GetByID resolves a secret by its UUID.
func (c *Client) GetByID(id string) (string, error) {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	if v, ok := c.byID[id]; ok {
		return v, nil
	}
	return "", fmt.Errorf("secret with id %q not found", id)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
