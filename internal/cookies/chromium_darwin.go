//go:build darwin

package cookies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// chromiumStore is one Chromium-family browser the active cookie provider does
// not cover. keychainService/keychainAccount name the macOS Keychain item
// holding its Safe Storage password; userDataDir is relative to
// ~/Library/Application Support.
type chromiumStore struct {
	browser         string
	keychainService string
	keychainAccount string
	userDataDir     string
}

// directStores lists what the direct reader covers. Only Arc is here: kooky has
// no browser package for it (browser/ holds chrome, chromium, brave, edge, …
// but nothing for Arc), and HackBrowserData does not discover it either, so an
// Arc-only GitHub login is invisible to both providers. Every other
// Chromium-family browser is left to the provider, which decrypts through the
// same Keychain path with far more platform coverage than this file has.
var directStores = []chromiumStore{
	{browser: "Arc", keychainService: "Arc Safe Storage", keychainAccount: "Arc", userDataDir: "Arc/User Data"},
}

// chromiumIV is the fixed IV Chromium uses for cookie values on macOS.
var chromiumIV = bytes.Repeat([]byte{' '}, aes.BlockSize)

const (
	chromiumSalt       = "saltysalt"
	chromiumIterations = 1003 // macOS; Linux uses 1
	chromiumKeyLen     = 16   // AES-128
	// chromiumDomainHashLen is the length of the SHA-256 of the cookie's host
	// key that Chromium prepends to the plaintext (domain-bound cookies, M127+).
	chromiumDomainHashLen = sha256.Size
)

// directReadRawCookies reads github.com cookies straight out of the cookie
// stores in directStores. Returning rawCookie rather than a finished session
// means these candidates go through exactly the same ranking as the provider's
// (see groupCandidates / selectSession), including the logged_in correlation.
//
// Absent browsers are not an error: a store whose directory or Keychain item is
// missing is skipped, and only a total failure to read anything is reported.
func directReadRawCookies() ([]rawCookie, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("locating application support directory: %w", err)
	}

	var out []rawCookie
	var errs []string
	for _, s := range directStores {
		root := filepath.Join(configDir, s.userDataDir)
		profiles, err := chromiumProfiles(root)
		if err != nil || len(profiles) == 0 {
			continue
		}
		key, err := chromiumKey(s)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", s.browser, err))
			continue
		}
		for _, profile := range profiles {
			raw, err := readChromiumCookies(filepath.Join(root, profile, "Cookies"), key)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s/%s: %v", s.browser, profile, err))
				continue
			}
			for i := range raw {
				raw[i].store = s.browser + "\x00" + profile
			}
			out = append(out, raw...)
		}
	}

	if len(out) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("direct cookie read failed: %s", strings.Join(errs, "; "))
	}
	return out, nil
}

// chromiumProfiles lists the profile directories under a user data dir that
// actually hold a cookie database.
func chromiumProfiles(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var profiles []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), "Cookies")); err == nil {
			profiles = append(profiles, e.Name())
		}
	}
	return profiles, nil
}

// chromiumKey derives the AES key for one browser from its Keychain password.
//
// The Keychain item holds base64 text, but Chromium feeds that text to PBKDF2
// verbatim — it is the password, not an encoding of one. Decoding it first
// derives a different key, and AES-CBC then returns plausible-looking bytes
// that are simply wrong: the padding check below is what catches that.
func chromiumKey(s chromiumStore) ([]byte, error) {
	out, err := exec.Command(
		"/usr/bin/security", "find-generic-password",
		"-s", s.keychainService,
		"-wa", s.keychainAccount,
	).Output()
	if err != nil {
		return nil, fmt.Errorf("reading %q from keychain: %w", s.keychainService, err)
	}
	password := strings.TrimSpace(string(out))
	if password == "" {
		return nil, fmt.Errorf("keychain item %q is empty", s.keychainService)
	}
	return pbkdf2.Key(sha1.New, password, []byte(chromiumSalt), chromiumIterations, chromiumKeyLen)
}

// readChromiumCookies pulls the github.com rows out of one cookie database.
//
// The database is copied first: the browser holds it open with WAL journaling,
// and reading in place both risks lock contention and can miss rows still in
// the -wal file. The read itself shells out to sqlite3 rather than linking a
// driver, keeping a stock `go build` free of cgo.
func readChromiumCookies(dbPath string, key []byte) ([]rawCookie, error) {
	tmpDir, err := os.MkdirTemp("", "gh-image-cookies-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if data, err := os.ReadFile(dbPath); err == nil {
		if err := os.WriteFile(filepath.Join(tmpDir, "Cookies"), data, 0o600); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if data, err := os.ReadFile(dbPath + suffix); err == nil {
			_ = os.WriteFile(filepath.Join(tmpDir, "Cookies"+suffix), data, 0o600)
		}
	}

	// hex() keeps binary ciphertext and any exotic byte in a plaintext value on
	// one line; host_key and name are Chromium-controlled and hold no '|'.
	const query = `SELECT host_key || '|' || name || '|' || hex(encrypted_value) || '|' || hex(value) ` +
		`FROM cookies WHERE host_key LIKE '%github.com';`
	out, err := exec.Command("sqlite3", filepath.Join(tmpDir, "Cookies"), query).Output()
	if err != nil {
		return nil, fmt.Errorf("sqlite3: %w", err)
	}

	var raw []rawCookie
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		if len(parts) != 4 {
			continue
		}
		host, name := parts[0], parts[1]
		value, err := chromiumValue(host, parts[2], parts[3], key)
		if err != nil || value == "" {
			continue
		}
		raw = append(raw, rawCookie{domain: host, name: name, value: value})
	}
	return raw, nil
}

// chromiumValue returns the cleartext for one row, decrypting when the value is
// encrypted and falling back to the plaintext column when it is not.
func chromiumValue(host, encHex, plainHex string, key []byte) (string, error) {
	if encHex == "" {
		plain, err := hex.DecodeString(plainHex)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}
	enc, err := hex.DecodeString(encHex)
	if err != nil {
		return "", err
	}
	return decryptChromiumValue(host, enc, key)
}

// decryptChromiumValue undoes Chromium's macOS cookie encryption: a "v10" tag,
// then AES-128-CBC under the derived key.
//
// Since M127 the plaintext is not the value alone but the SHA-256 of the
// cookie's host key followed by the value, so that a stolen ciphertext cannot be
// replanted under a different domain. The hash is only stripped when it matches
// the row's own host key, which leaves values written by older Chromium builds
// (no prefix) intact instead of eating their first 32 bytes.
func decryptChromiumValue(host string, enc, key []byte) (string, error) {
	const tag = "v10"
	if len(enc) < len(tag) || string(enc[:len(tag)]) != tag {
		return "", fmt.Errorf("unexpected encryption version %q", enc[:min(len(tag), len(enc))])
	}
	ciphertext := enc[len(tag):]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext length %d is not a whole number of blocks", len(ciphertext))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, chromiumIV).CryptBlocks(plaintext, ciphertext)

	plaintext, err = stripPKCS7(plaintext)
	if err != nil {
		// A wrong key decrypts to noise, which almost never carries valid
		// padding — so this is the check that keeps garbage out of a Cookie
		// header rather than a statement about the file.
		return "", err
	}

	if len(plaintext) >= chromiumDomainHashLen {
		want := sha256.Sum256([]byte(host))
		if bytes.Equal(plaintext[:chromiumDomainHashLen], want[:]) {
			plaintext = plaintext[chromiumDomainHashLen:]
		}
	}
	return string(plaintext), nil
}

// stripPKCS7 removes and verifies PKCS#7 padding. Verifying every byte, not just
// the last one, is what makes it usable as a decryption sanity check.
func stripPKCS7(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("padded length %d is not a whole number of blocks", len(b))
	}
	pad := int(b[len(b)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(b) {
		return nil, fmt.Errorf("invalid padding length %d", pad)
	}
	for _, c := range b[len(b)-pad:] {
		if int(c) != pad {
			return nil, fmt.Errorf("inconsistent padding")
		}
	}
	return b[:len(b)-pad], nil
}
