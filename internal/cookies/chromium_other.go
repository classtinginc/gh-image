//go:build !darwin

package cookies

// directReadRawCookies is a no-op off macOS. The direct reader exists to cover
// Arc, which ships on macOS only; everywhere else the build-tag-selected
// provider is the whole story.
func directReadRawCookies() ([]rawCookie, error) { return nil, nil }
