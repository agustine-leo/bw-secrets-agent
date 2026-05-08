package bwclient

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// ── derive_shareable_key — cross-implementation vectors ────────────────────
//
// These are the expected outputs from bitwarden-crypto's own tests
// (crates/bitwarden-crypto/src/keys/shareable_key.rs::test_derive_shareable_key).
// If our implementation drifts from upstream, this test breaks.

func TestDeriveShareableKey_BitwardenVectors(t *testing.T) {
	tests := []struct {
		name     string
		seed     []byte
		nameArg  string
		info     string
		expected string // base64 of the 64-byte derived key
	}{
		{
			name:     "name=test_key, info=None",
			seed:     []byte("&/$%F1a895g67HlX"),
			nameArg:  "test_key",
			info:     "",
			expected: "4PV6+PcmF2w7YHRatvyMcVQtI7zvCyssv/wFWmzjiH6Iv9altjmDkuBD1aagLVaLezbthbSe+ktR+U6qswxNnQ==",
		},
		{
			name:     "name=test_key, info=test",
			seed:     []byte("67t9b5g67$%Dh89n"),
			nameArg:  "test_key",
			info:     "test",
			expected: "F9jVQmrACGx9VUPjuzfMYDjr726JtL300Y3Yg+VYUnVQtQ1s8oImJ5xtp1KALC9h2nav04++1LDW4iFD+infng==",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveShareableKey(tc.seed, tc.nameArg, tc.info)
			if err != nil {
				t.Fatalf("deriveShareableKey: %v", err)
			}
			gotB64 := base64.StdEncoding.EncodeToString(got)
			if gotB64 != tc.expected {
				t.Errorf("derived key mismatch\n  want: %s\n  got:  %s", tc.expected, gotB64)
			}
		})
	}
}

// ── parseAccessToken — Bitwarden test vector + malformed inputs ────────────

// The full BWS test token from bitwarden-core's `can_decode_access_token`
// test, with the expected post-derivation 64-byte working key. This pins
// both the parser and the access-token key derivation.
func TestParseAccessToken_BitwardenVector(t *testing.T) {
	const (
		token       = "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ=="
		wantID      = "ec2c1d46-6a4b-4751-a310-af9601317f2d"
		wantSecret  = "C2IgxjjLF7qSshsbwe8JGcbM075YXw"
		wantDerived = "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg=="
	)

	pt, err := parseAccessToken(token)
	if err != nil {
		t.Fatalf("parseAccessToken: %v", err)
	}
	if pt.AccessTokenID != wantID {
		t.Errorf("AccessTokenID: want %q, got %q", wantID, pt.AccessTokenID)
	}
	if pt.ClientSecret != wantSecret {
		t.Errorf("ClientSecret: want %q, got %q", wantSecret, pt.ClientSecret)
	}
	if got := base64.StdEncoding.EncodeToString(pt.EncryptionKey); got != wantDerived {
		t.Errorf("derived key mismatch\n  want: %s\n  got:  %s", wantDerived, got)
	}
}

func TestParseAccessToken_Malformed(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"missing colon", "0.uuid.secret"},
		{"missing dot", "0uuidsecret:key"},
		{"wrong version", "1.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ=="},
		{"non-16-byte key", "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:" + base64.StdEncoding.EncodeToString(make([]byte, 8))},
		{"invalid base64 key", "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.secret:!!notb64!!"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseAccessToken(tc.token); err == nil {
				t.Errorf("expected error for %q, got nil", tc.token)
			}
		})
	}
}

// ── decryptEncString — round-trip with a known key ─────────────────────────

func TestDecryptEncString_RoundTrip(t *testing.T) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	plaintexts := [][]byte{
		[]byte("hello"),
		[]byte("a value with == padding boundaries"),
		make([]byte, 0),
		bytesRepeat(0xAB, 64),
	}
	for i, pt := range plaintexts {
		enc := encryptEncString(t, pt, key)
		got, err := decryptEncString(enc, key)
		if err != nil {
			t.Fatalf("case %d decrypt: %v", i, err)
		}
		if string(got) != string(pt) {
			t.Errorf("case %d round-trip mismatch:\n  want: %q\n  got:  %q", i, pt, got)
		}
	}
}

func TestDecryptEncString_BadMAC(t *testing.T) {
	key := make([]byte, 64)
	rand.Read(key)
	enc := encryptEncString(t, []byte("hello"), key)

	// Flip a bit in the MAC (last component).
	parts := strings.Split(enc, "|")
	mac, _ := base64.StdEncoding.DecodeString(parts[2])
	mac[0] ^= 0x01
	parts[2] = base64.StdEncoding.EncodeToString(mac)
	tampered := strings.Join(parts, "|")

	if _, err := decryptEncString(tampered, key); err == nil {
		t.Error("expected MAC verification to fail, got nil error")
	}
}

func TestDecryptEncString_BadInput(t *testing.T) {
	key := make([]byte, 64)
	tests := []struct {
		name, in string
	}{
		{"missing parts", "2.aGVsbG8=|aGVsbG8="},
		{"invalid b64 iv", "2.!|" + base64.StdEncoding.EncodeToString([]byte("ct")) + "|" + base64.StdEncoding.EncodeToString([]byte("mac"))},
		{"empty", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decryptEncString(tc.in, key); err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

// ── pkcs7Unpad ─────────────────────────────────────────────────────────────

func TestPKCS7Unpad(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    []byte
		wantErr bool
	}{
		{"single byte pad", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1}, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, false},
		{"full block pad", bytesRepeat(16, 16), nil, false}, // 16 bytes of 0x10 → empty plaintext
		{"empty input", []byte{}, nil, true},
		{"zero pad byte", []byte{1, 2, 0}, nil, true},
		{"pad larger than block", []byte{1, 2, 17}, nil, true},
		{"inconsistent pad", []byte{1, 2, 3, 2}, nil, true}, // claims pad=2 but second-to-last byte is 3
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pkcs7Unpad(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != string(tc.want) {
				t.Errorf("want %v, got %v", tc.want, got)
			}
		})
	}
}

// ── JWT extraction ─────────────────────────────────────────────────────────

func TestOrgIDFromJWT(t *testing.T) {
	// Hand-rolled minimal JWT: header.{"organization":"abc-123"}.signature
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"organization":"abc-123","sub":"x"}`))
	jwt := header + "." + payload + ".sig"

	if got := orgIDFromJWT(jwt); got != "abc-123" {
		t.Errorf("want abc-123, got %q", got)
	}

	// Falls back to organizationId.
	payload = base64.RawURLEncoding.EncodeToString([]byte(`{"organizationId":"def-456"}`))
	jwt = header + "." + payload + ".sig"
	if got := orgIDFromJWT(jwt); got != "def-456" {
		t.Errorf("want def-456, got %q", got)
	}

	// Returns empty when no claim present.
	payload = base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	jwt = header + "." + payload + ".sig"
	if got := orgIDFromJWT(jwt); got != "" {
		t.Errorf("want empty, got %q", got)
	}

	// Garbage in → empty out (not a panic).
	if got := orgIDFromJWT("not.a.jwt"); got != "" {
		t.Errorf("want empty, got %q", got)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

// encryptEncString produces a Bitwarden type-2 EncString from plaintext + key,
// using the same primitives we decrypt with — so the round-trip test exercises
// the full path even when we don't have an upstream-encrypted vector at hand.
func encryptEncString(t *testing.T, plaintext, key []byte) string {
	t.Helper()
	if len(key) != 64 {
		t.Fatalf("key must be 64 bytes, got %d", len(key))
	}
	aesKey, macKey := key[:32], key[32:]

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand iv: %v", err)
	}

	// PKCS7-pad to AES block size.
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(append([]byte{}, plaintext...), bytesRepeat(byte(padLen), padLen)...)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ct)
	mac := h.Sum(nil)

	return "2." +
		base64.StdEncoding.EncodeToString(iv) + "|" +
		base64.StdEncoding.EncodeToString(ct) + "|" +
		base64.StdEncoding.EncodeToString(mac)
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
