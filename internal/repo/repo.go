package repo

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Info holds the owner, repo name, and numeric ID for a GitHub repository.
type Info struct {
	Owner string
	Name  string
	ID    int
}

var (
	sshRemoteRe   = regexp.MustCompile(`git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$`)
	httpsRemoteRe = regexp.MustCompile(`https://github\.com/([^/]+)/([^/]+?)(?:\.git)?$`)
)

// FromRemote infers the GitHub owner/repo from the git remote in the current directory.
func FromRemote() (owner, name string, err error) {
	out, err := exec.Command("git", "remote", "get-url", "origin").Output()
	if err != nil {
		return "", "", fmt.Errorf("not a git repository or no 'origin' remote configured")
	}
	remote := strings.TrimSpace(string(out))

	if m := sshRemoteRe.FindStringSubmatch(remote); m != nil {
		return m[1], m[2], nil
	}
	if m := httpsRemoteRe.FindStringSubmatch(remote); m != nil {
		return m[1], m[2], nil
	}

	return "", "", fmt.Errorf("could not parse GitHub owner/repo from remote URL: %s", remote)
}

// LookupID resolves the numeric repository ID via the gh CLI.
func LookupID(owner, name string) (int, error) {
	out, err := exec.Command("gh", "api", fmt.Sprintf("repos/%s/%s", owner, name), "--jq", ".id").Output()
	if err != nil {
		return 0, fmt.Errorf("failed to look up repo ID for %s/%s (is gh CLI installed and authenticated?): %w", owner, name, err)
	}
	id, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, fmt.Errorf("unexpected repo ID format: %s", strings.TrimSpace(string(out)))
	}
	return id, nil
}

// Resolve returns full repo info. If owner/name are empty, it infers from the git remote.
func Resolve(owner, name string) (*Info, error) {
	if owner == "" || name == "" {
		var err error
		owner, name, err = FromRemote()
		if err != nil {
			return nil, err
		}
	}

	id, err := LookupID(owner, name)
	if err != nil {
		return nil, err
	}

	return &Info{Owner: owner, Name: name, ID: id}, nil
}
