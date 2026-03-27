# Architecture

## Overview

`gh-image` is a Go CLI tool distributed as a `gh` extension. It uploads images to GitHub using the same internal API that the web UI uses when you drag-and-drop or paste an image. The tool handles browser cookie extraction, CSRF token negotiation, and S3 presigned uploads, then prints the resulting markdown image reference to stdout.

## Project Structure

```
gh-image/
├── main.go                          # CLI entrypoint, argument parsing
├── go.mod
├── go.sum
├── internal/
│   ├── cookies/
│   │   └── cookies.go               # Chrome cookie extraction via kooky
│   ├── upload/
│   │   ├── upload.go                # Orchestrates the 3-step upload flow
│   │   ├── token.go                 # Fetches uploadToken from repo page
│   │   └── s3.go                    # S3 presigned multipart upload
│   └── repo/
│       └── repo.go                  # Infers owner/repo from git remote, resolves repo ID
├── documentation/
│   ├── architecture.md              # This file
│   └── github-image-upload-flow.md  # Reverse-engineered upload protocol
└── .github/
    └── workflows/
        └── release.yml              # GoReleaser cross-compilation + release
```

## Component Design

### 1. Cookie Extraction (`internal/cookies/`)

Reads the GitHub `user_session` cookie from the local Chrome cookie database.

**Dependency:** [`browserutils/kooky`](https://github.com/browserutils/kooky) — a pure Go library that handles:
- Locating Chrome's SQLite cookie database on disk
- Retrieving the encryption key from macOS Keychain
- AES-128-CBC decryption (PBKDF2-derived key, `saltysalt`, 1003 iterations)
- Cookie DB schema differences across Chromium versions

**Interface:**

```go
// GetGitHubSession returns the user_session cookie for github.com.
// It searches Chrome, Brave, Edge, and Chromium in order, returning
// the cookie from the first browser with a valid GitHub session.
func GetGitHubSession() (*http.Cookie, error)
```

The only cookie needed from the browser is `user_session`. The `__Host-user_session_same_site` cookie is a duplicate of `user_session` with a stricter SameSite policy — it has the same value, so the client synthesizes it from `user_session` rather than reading it separately. The `_gh_sess` cookie rotates with each GitHub response and is managed automatically by the HTTP client's cookie jar — it does not need to be read from the browser's cookie store. Using `kooky` means we don't maintain any crypto or Keychain code ourselves.

### 2. Repository Resolution (`internal/repo/`)

Resolves the target GitHub repository's owner, name, and numeric ID.

If `--repo` is not provided, the tool infers `owner/repo` from the current git workspace by parsing the `origin` remote URL (`git remote get-url origin`). This supports both SSH (`git@github.com:owner/repo.git`) and HTTPS (`https://github.com/owner/repo.git`) remote formats via regex.

The numeric repository ID is resolved via the GitHub REST API (`gh api repos/{owner}/{repo} --jq .id`).

```go
// FromRemote infers the GitHub owner/repo from the git remote in the current directory.
func FromRemote() (owner, name string, err error)

// LookupID resolves the numeric repository ID via the gh CLI.
func LookupID(owner, name string) (int, error)

// Resolve returns full repo info. If owner/name are empty, it infers from the git remote.
func Resolve(owner, name string) (*Info, error)
```

### 3. Upload Flow (`internal/upload/`)

Implements the 3-step upload protocol documented in [github-image-upload-flow.md](github-image-upload-flow.md). All HTTP requests use a shared `http.Client` with a cookie jar so that `_gh_sess` rotation is handled automatically.

#### Token Retrieval (`token.go`)

Fetches the repository page and extracts the `uploadToken` from the embedded JavaScript payload. This token is specific to the upload endpoint — standard form CSRF tokens do not work.

```go
// GetUploadToken fetches the repo page and extracts the uploadToken
// from the JS payload. Requires authenticated cookies in the client.
func GetUploadToken(client *http.Client, owner, repo string) (string, error)
```

#### Upload Orchestration (`upload.go`)

Coordinates the full flow for a single image:

```
GetUploadToken()
        │
        ▼
requestPolicy()        ──→  POST /upload/policies/assets
        │                    Returns: S3 form fields, asset ID,
        │                    asset_upload_authenticity_token
        ▼
uploadToS3()           ──→  POST {s3_upload_url}
        │                    Multipart form with presigned fields + file
        │                    No GitHub auth needed
        ▼
finalizeUpload()       ──→  PUT /upload/assets/{asset_id}
        │                    Uses asset_upload_authenticity_token from step 1
        ▼
    Returns asset href URL
```

**Key implementation details:**
- The `form` fields from the policy response must be sent to S3 exactly as-is. Adding extra fields (e.g., duplicate `Content-Type`) causes S3 to reject the upload with a 403 policy violation.
- The `file` field must be the **last** field in the multipart form.
- The finalize step uses `asset_upload_authenticity_token` from the policy response, **not** the `uploadToken` from step 0. Each step produces the token needed for the next step (see [Token Relationships](github-image-upload-flow.md#token-relationships)).
- The finalize step is mandatory — without it, the asset URL returns 404.

#### S3 Upload (`s3.go`)

Handles the multipart form construction for the S3 presigned upload. Separated from the main orchestration because the S3 request has different requirements (no cookies, no GitHub headers, just the presigned form fields and file data).

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│  User: gh image screenshot.png --repo o/r                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │   Cookie Extraction  │
                │   (kooky + Keychain) │
                └──────────┬───────────┘
                           │ user_session
                           ▼
                ┌──────────────────────┐
                │  Fetch uploadToken   │
                │  GET /repo page      │
                └──────────┬───────────┘
                           │ uploadToken
                           ▼
                ┌──────────────────────┐
                │  Request Policy      │
                │  POST /upload/       │
                │  policies/assets     │
                └──────────┬───────────┘
                           │ S3 presigned form
                           │ asset_upload_authenticity_token
                           ▼
                ┌──────────────────────┐
                │  Upload to S3        │
                │  POST s3.aws.com     │
                │  (no GitHub auth)    │
                └──────────┬───────────┘
                           │ 204 OK
                           ▼
                ┌──────────────────────┐
                │  Finalize            │
                │  PUT /upload/        │
                │  assets/{id}         │
                └───────────┬──────────┘
                           │ asset href URL
                           ▼
                ┌──────────────────────┐
                │  Print markdown      │
                │  to stdout           │
                └──────────────────────┘
```

## Authentication Model

The tool uses browser cookies for all GitHub requests:

| Action | Auth Method | Source |
|---|---|---|
| Steps 0, 1, 3 (GitHub requests) | `user_session` + `__Host-user_session_same_site` cookies | Browser cookie DB (via kooky) |
| Step 2 (S3 upload) | None | Presigned policy from step 1 |
| Repo ID lookup | OAuth token | `gh` CLI (via `gh auth`) |

The cookie and `gh` CLI auth paths are independent — the cookie provides a browser-equivalent session for the undocumented upload API, while `gh` handles the standard REST API for looking up the numeric repository ID.

## Distribution

Built as a [`gh` CLI extension](https://cli.github.com/manual/gh_extension):

- Repository is named `gh-image` so it installs as `gh image`
- GoReleaser builds binaries for macOS (arm64, amd64), Linux (amd64, arm64), and Windows (amd64) on tagged releases
- `gh extension install` auto-detects the user's platform and downloads the correct binary from the GitHub Release
- Single static binary, no runtime dependencies

### Release Flow

```
git tag v0.1.0
git push --tags
→ GitHub Actions triggers
  → GoReleaser cross-compiles
  → Attaches binaries to GitHub Release
→ Users: gh extension install drogers0/gh-image
```

## Dependencies

| Dependency | Purpose |
|---|---|
| [`browserutils/kooky`](https://github.com/browserutils/kooky) | Chrome cookie extraction (Keychain + AES + SQLite) |
| Go standard library `net/http` | HTTP client for upload flow |
| Go standard library `mime/multipart` | Multipart form construction |
| Go standard library `encoding/json` | JSON parsing |
| Go standard library `regexp` | uploadToken extraction |

## Platform Notes

- **macOS:** Fully supported. A Keychain prompt may appear on first use to authorize access to the browser's cookie encryption key. Click "Always Allow" to avoid repeated prompts.
- **Linux:** kooky supports Linux (GNOME Keyring / kwallet for Chrome key storage). The upload flow is platform-agnostic. Main gap is testing.
- **Windows:** kooky supports Windows (DPAPI for Chrome cookie decryption). Binaries are built for Windows amd64. Main gap is testing.

## Future Considerations

- **Firefox support:** kooky supports Firefox cookies. Would need to detect which browser has a GitHub session.
- **Clipboard image support:** Accept image data from clipboard (`gh image paste --repo o/r`) instead of requiring a file path.
- **Token caching:** The `uploadToken` could be cached briefly to avoid fetching the repo page on every upload. The presigned S3 policy expires in ~30 minutes, so caching is safe within that window.
