// Package update checks whether a newer CMD-Chat release has been published.
//
// The check is deliberately small and deliberately optional. It reads the
// repository's latest release from the public GitHub API, compares the tag with
// the version this binary was built as, and reports a newer one. It sends
// nothing about the user, it is never required for the chat to work, and every
// failure is silent: an update notice is a convenience, and a peer-to-peer chat
// tool should not lecture someone about their network on the way in.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Repo is the repository releases are published to.
const Repo = "ESP32-S3/CMD-Chat"

// APIBase is the public GitHub API. It is a variable so tests can point the
// check at a local server instead of the network.
var APIBase = "https://api.github.com"

// DisableEnv turns the check off entirely. Set it to any non-empty value.
const DisableEnv = "CMD_CHAT_NO_UPDATE_CHECK"

// Timeout bounds the whole check. Launch must not wait on the network, so this
// is short and the caller runs it in the background regardless.
const Timeout = 6 * time.Second

// Release is a published release newer than the running binary.
type Release struct {
	Version string `json:"tag_name"`
	URL     string `json:"html_url"`
	Name    string `json:"name"`
}

// Disabled reports whether the user has switched the check off.
func Disabled() bool { return strings.TrimSpace(os.Getenv(DisableEnv)) != "" }

// Check returns the latest release when it is newer than current, and nil when
// it is not.
//
// A nil result with a nil error means "you are up to date"; callers do not need
// to tell those two cases apart to behave correctly.
func Check(ctx context.Context, current string) (*Release, error) {
	if Disabled() {
		return nil, nil
	}

	// A build without a version stamped in cannot be compared against anything,
	// and telling a developer running `go build` that they are out of date would
	// be noise rather than news.
	if _, ok := parse(current); !ok {
		return nil, fmt.Errorf("update: running version %q is not a release build", current)
	}

	url := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(APIBase, "/"), Repo)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "cmd-chat/"+current)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: GitHub returned %s", response.Status)
	}

	var latest Release
	if err := json.NewDecoder(response.Body).Decode(&latest); err != nil {
		return nil, err
	}
	if !Newer(latest.Version, current) {
		return nil, nil
	}
	return &latest, nil
}

// Newer reports whether latest is a strictly higher version than current.
//
// Anything unparseable on either side reports false: a release tag that does not
// look like a version is not grounds for telling someone to upgrade.
func Newer(latest, current string) bool {
	l, ok := parse(latest)
	if !ok {
		return false
	}
	c, ok := parse(current)
	if !ok {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// parse reads a major.minor.patch version, with an optional leading "v" and an
// optional pre-release or build suffix.
//
// Pre-release identifiers are dropped rather than ordered. CMD-Chat has never
// published one, and guessing at an ordering nobody uses would add a way to be
// wrong for no benefit.
func parse(version string) ([3]int, bool) {
	var out [3]int

	v := strings.TrimSpace(version)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return out, false
	}

	fields := strings.Split(v, ".")
	if len(fields) != 3 {
		return out, false
	}
	for i, field := range fields {
		n, err := strconv.Atoi(field)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
