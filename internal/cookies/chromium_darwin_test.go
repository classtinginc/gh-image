//go:build darwin

package cookies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// keychainPassword is shaped like the real thing: Chromium stores base64 text of
// 16 random bytes in the Keychain, and that text is the PBKDF2 password.
const keychainPassword = "cGFzc3dvcmRwYXNzd29yZA=="

func testKey(t *testing.T, password string) []byte {
	t.Helper()
	key, err := pbkdf2.Key(sha1.New, password, []byte(chromiumSalt), chromiumIterations, chromiumKeyLen)
	if err != nil {
		t.Fatalf("deriving key: %v", err)
	}
	return key
}

// encryptValue reproduces how Chromium writes a cookie on macOS. withPrefix
// selects the M127+ domain-bound layout (SHA-256 of the host key ahead of the
// value) over the older value-only one.
func encryptValue(t *testing.T, host, value string, key []byte, withPrefix bool) []byte {
	t.Helper()
	plain := []byte(value)
	if withPrefix {
		sum := sha256.Sum256([]byte(host))
		plain = append(sum[:], plain...)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, chromiumIV).CryptBlocks(out, plain)
	return append([]byte("v10"), out...)
}

func TestDecryptChromiumValue(t *testing.T) {
	key := testKey(t, keychainPassword)

	tests := []struct {
		name       string
		host       string
		value      string
		withPrefix bool
	}{
		// The host-only and leading-dot forms hash differently, and the prefix
		// is built from the host key exactly as the database stores it — so a
		// reader that normalizes the dot away would strip nothing here.
		{name: "domain bound host only", host: "github.com", value: "abc123sessiontoken", withPrefix: true},
		{name: "domain bound leading dot", host: ".github.com", value: "yes", withPrefix: true},
		// Pre-M127 stores hold the value alone; those must survive unchanged
		// rather than lose their first 32 bytes.
		{name: "legacy no prefix", host: "github.com", value: "legacy-session-value", withPrefix: false},
		// A value long enough to span blocks, so padding removal is exercised
		// on something other than a single short block.
		{name: "multi block", host: "github.com", value: string(bytes.Repeat([]byte("x"), 100)), withPrefix: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := encryptValue(t, tt.host, tt.value, key, tt.withPrefix)
			got, err := decryptChromiumValue(tt.host, enc, key)
			if err != nil {
				t.Fatalf("decryptChromiumValue: %v", err)
			}
			if got != tt.value {
				t.Errorf("got %q, want %q", got, tt.value)
			}
		})
	}
}

// TestDecryptChromiumValueRejectsBase64DecodedKey pins the fix for the bug this
// reader shipped with: the Keychain password was base64-decoded before key
// derivation. That yields a valid AES key over the wrong bytes, so decryption
// succeeds mechanically and returns noise. Padding verification is what turns
// that into an error instead of a Cookie header full of control bytes.
func TestDecryptChromiumValueRejectsBase64DecodedKey(t *testing.T) {
	const host = "github.com"
	enc := encryptValue(t, host, "abc123sessiontoken", testKey(t, keychainPassword), true)

	decoded, err := base64.StdEncoding.DecodeString(keychainPassword)
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	got, err := decryptChromiumValue(host, enc, testKey(t, string(decoded)))
	if err == nil {
		t.Fatalf("got %q, want an error: a key derived from the decoded password must not yield a value", got)
	}
}

func TestDecryptChromiumValueRejectsMalformed(t *testing.T) {
	key := testKey(t, keychainPassword)
	tests := []struct {
		name string
		enc  []byte
	}{
		{name: "empty", enc: nil},
		{name: "unknown version", enc: append([]byte("v20"), bytes.Repeat([]byte{0}, aes.BlockSize)...)},
		{name: "no ciphertext", enc: []byte("v10")},
		{name: "partial block", enc: append([]byte("v10"), bytes.Repeat([]byte{0}, aes.BlockSize-1)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := decryptChromiumValue("github.com", tt.enc, key); err == nil {
				t.Errorf("got %q, want an error", got)
			}
		})
	}
}

func TestStripPKCS7(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    string
		wantErr bool
	}{
		{name: "full block of padding", in: bytes.Repeat([]byte{16}, 16), want: ""},
		{name: "one byte of padding", in: append(bytes.Repeat([]byte{'a'}, 15), 1), want: "aaaaaaaaaaaaaaa"},
		{name: "inconsistent padding", in: append(bytes.Repeat([]byte{'a'}, 14), 2, 3), wantErr: true},
		{name: "padding length zero", in: append(bytes.Repeat([]byte{'a'}, 15), 0), wantErr: true},
		{name: "not block aligned", in: bytes.Repeat([]byte{1}, 15), wantErr: true},
		{name: "empty", in: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := stripPKCS7(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("got %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("stripPKCS7: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
