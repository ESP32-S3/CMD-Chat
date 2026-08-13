package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewerOrdersReleases(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v2.1.5", "v2.1.4", true},
		{"v2.2.0", "v2.1.4", true},
		{"v3.0.0", "v2.9.9", true},
		{"v2.1.4", "v2.1.4", false},
		{"v2.1.3", "v2.1.4", false},
		{"v2.0.4", "v2.1.4", false},
		{"v1.0.4", "v2.1.4", false},

		// A minor bump that lowers the patch number is still an upgrade. This is
		// the shape of this project's own history: v2.0.4 -> v2.1.4 -> v2.1.5.
		{"v2.1.0", "v2.0.9", true},

		// Missing or malformed versions never trigger a notice.
		{"", "v2.1.4", false},
		{"v2.1.4", "", false},
		{"latest", "v2.1.4", false},
		{"v2.1", "v2.1.4", false},
		{"v2.1.4.1", "v2.1.4", false},
		{"vX.Y.Z", "v2.1.4", false},
		{"v2.1.5", "dev", false},

		// Tags with and without the leading v compare the same.
		{"2.1.5", "v2.1.4", true},
		{"v2.1.5", "2.1.4", true},

		// Suffixes are dropped rather than ordered.
		{"v2.1.5-rc1", "v2.1.4", true},
		{"v2.1.4-rc1", "v2.1.4", false},
	}

	for _, tc := range cases {
		if got := Newer(tc.latest, tc.current); got != tc.want {
			t.Errorf("Newer(%q, %q) = %t, want %t", tc.latest, tc.current, got, tc.want)
		}
	}
}

// TestCheckReportsNewerRelease runs the whole check against a stand-in for the
// GitHub API, so the parsing and the comparison are covered without the network.
func TestCheckReportsNewerRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/repos/"+Repo+"/releases/latest"; got != want {
			t.Errorf("requested %q, want %q", got, want)
		}
		if r.Header.Get("User-Agent") == "" {
			t.Error("no User-Agent sent; GitHub rejects requests without one")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://example.invalid/rel","name":"CMD-Chat v9.9.9"}`))
	}))
	defer server.Close()

	t.Setenv(DisableEnv, "")
	restore := APIBase
	APIBase = server.URL
	defer func() { APIBase = restore }()

	release, err := Check(context.Background(), "v2.1.4")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if release == nil {
		t.Fatal("Check reported no update, want v9.9.9")
	}
	if release.Version != "v9.9.9" {
		t.Errorf("Version = %q, want v9.9.9", release.Version)
	}
	if release.URL != "https://example.invalid/rel" {
		t.Errorf("URL = %q, want the release page", release.URL)
	}
}

func TestCheckIsQuietWhenUpToDate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v2.1.4"}`))
	}))
	defer server.Close()

	t.Setenv(DisableEnv, "")
	restore := APIBase
	APIBase = server.URL
	defer func() { APIBase = restore }()

	release, err := Check(context.Background(), "v2.1.4")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if release != nil {
		t.Fatalf("Check reported %q as an update to the same version", release.Version)
	}
}

// TestCheckHonoursOptOut keeps the switch meaningful: no request is made at all.
func TestCheckHonoursOptOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the update check contacted GitHub with the opt-out set")
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9"}`))
	}))
	defer server.Close()

	t.Setenv(DisableEnv, "1")
	restore := APIBase
	APIBase = server.URL
	defer func() { APIBase = restore }()

	release, err := Check(context.Background(), "v2.1.4")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if release != nil {
		t.Fatal("Check returned a release with the opt-out set")
	}
}

// TestCheckSkipsUnversionedBuilds keeps `go build` output from being told it is
// out of date on every launch.
func TestCheckSkipsUnversionedBuilds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the update check contacted GitHub for a build with no version")
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9"}`))
	}))
	defer server.Close()

	t.Setenv(DisableEnv, "")
	restore := APIBase
	APIBase = server.URL
	defer func() { APIBase = restore }()

	if _, err := Check(context.Background(), "dev"); err == nil {
		t.Fatal("Check accepted a build with no version stamped in")
	}
}

// TestCheckSurvivesABadResponse covers the failure path that matters most: the
// caller must get an error, never a panic and never a bogus update notice.
func TestCheckSurvivesABadResponse(t *testing.T) {
	for _, body := range []string{"", "not json", "{"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))

		t.Setenv(DisableEnv, "")
		restore := APIBase
		APIBase = server.URL

		release, err := Check(context.Background(), "v2.1.4")
		if release != nil {
			t.Errorf("body %q produced an update notice", body)
		}
		if err == nil {
			t.Errorf("body %q returned no error", body)
		}

		APIBase = restore
		server.Close()
	}
}

func TestCheckReportsHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	t.Setenv(DisableEnv, "")
	restore := APIBase
	APIBase = server.URL
	defer func() { APIBase = restore }()

	release, err := Check(context.Background(), "v2.1.4")
	if release != nil {
		t.Fatal("a rate-limited API produced an update notice")
	}
	if err == nil {
		t.Fatal("a 403 returned no error")
	}
}
