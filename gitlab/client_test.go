package usp_gitlab

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/refractionPOINT/go-uspclient"
	"github.com/refractionPOINT/usp-adapters/utils"
)

func testClientOptions() uspclient.ClientOptions {
	return uspclient.ClientOptions{
		Identity: uspclient.Identity{
			Oid:             "c1ffedc0-ffee-4a1e-b1a5-abc123def456",
			InstallationKey: "e9a3bcdf-efa2-47ae-b6df-579a02f3a54d",
		},
		Platform:      "json",
		SensorSeedKey: "test-gitlab",
	}
}

func TestValidateDefaults(t *testing.T) {
	c := GitLabConfig{
		ClientOptions: testClientOptions(),
		Token:         "glpat-xxxx",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	if c.URL != defaultURL {
		t.Errorf("url = %q, expected %q", c.URL, defaultURL)
	}
	if c.Scope != scopeInstance {
		t.Errorf("scope = %q, expected %q", c.Scope, scopeInstance)
	}
	if c.EventTypes != eventTypeAudit {
		t.Errorf("event_types = %q, expected %q", c.EventTypes, eventTypeAudit)
	}
	if c.PollIntervalSec != defaultPollIntervalSec {
		t.Errorf("poll_interval_sec = %d, expected %d", c.PollIntervalSec, defaultPollIntervalSec)
	}
}

func TestValidateURLNormalization(t *testing.T) {
	for in, expected := range map[string]string{
		"gitlab.example.com":                 "https://gitlab.example.com",
		"https://gitlab.example.com/":        "https://gitlab.example.com",
		"https://gitlab.example.com/api/v4":  "https://gitlab.example.com",
		"https://gitlab.example.com/api/v4/": "https://gitlab.example.com",
		"http://gitlab.internal:8080":        "http://gitlab.internal:8080",
	} {
		c := GitLabConfig{
			ClientOptions: testClientOptions(),
			Token:         "glpat-xxxx",
			URL:           in,
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate(%q): %v", in, err)
		}
		if c.URL != expected {
			t.Errorf("url for %q = %q, expected %q", in, c.URL, expected)
		}
	}
}

func TestValidateRejectsBadConfigs(t *testing.T) {
	for name, c := range map[string]GitLabConfig{
		"missing token": {
			ClientOptions: testClientOptions(),
		},
		"bad scope": {
			ClientOptions: testClientOptions(),
			Token:         "glpat-xxxx",
			Scope:         "namespace",
		},
		"group without entity": {
			ClientOptions: testClientOptions(),
			Token:         "glpat-xxxx",
			Scope:         scopeGroup,
		},
		"instance with entity": {
			ClientOptions: testClientOptions(),
			Token:         "glpat-xxxx",
			EntityIDs:     "42",
		},
		"bad event type": {
			ClientOptions: testClientOptions(),
			Token:         "glpat-xxxx",
			EventTypes:    "vulnerabilities",
		},
		"group activity events": {
			ClientOptions: testClientOptions(),
			Token:         "glpat-xxxx",
			Scope:         scopeGroup,
			EntityIDs:     "42",
			EventTypes:    eventTypeActivity,
		},
		"bad start time": {
			ClientOptions: testClientOptions(),
			Token:         "glpat-xxxx",
			StartTime:     "2026-09-14 00:00:00",
		},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
}

func TestBuildStreamsPaths(t *testing.T) {
	c := GitLabConfig{
		ClientOptions: testClientOptions(),
		Token:         "glpat-xxxx",
		Scope:         scopeProject,
		EntityIDs:     "42, mygroup/myproject",
		EventTypes:    "audit_events,events",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	streams, err := c.buildStreams()
	if err != nil {
		t.Fatalf("buildStreams(): %v", err)
	}
	if len(streams) != 4 {
		t.Fatalf("got %d streams, expected 4", len(streams))
	}
	expected := map[string]bool{
		"/api/v4/projects/42/audit_events":                  true,
		"/api/v4/projects/mygroup%2Fmyproject/audit_events": true,
		"/api/v4/projects/42/events":                        true,
		"/api/v4/projects/mygroup%2Fmyproject/events":       true,
	}
	for _, s := range streams {
		if !expected[s.path] {
			t.Errorf("unexpected stream path: %s", s.path)
		}
		delete(expected, s.path)
	}
	for path := range expected {
		t.Errorf("missing stream path: %s", path)
	}
}

func TestParseNextLink(t *testing.T) {
	for in, expected := range map[string]string{
		"": "",
		`<https://gitlab.com/api/v4/audit_events?id_after=5&per_page=100>; rel="next", <https://gitlab.com/api/v4/audit_events?per_page=100>; rel="first"`: "https://gitlab.com/api/v4/audit_events?id_after=5&per_page=100",
		`<https://gitlab.com/api/v4/audit_events?per_page=100>; rel="first", <https://gitlab.com/api/v4/audit_events?page=9>; rel="last"`:                  "",
		`<https://gitlab.com/api/v4/events?page=2>; rel=next`: "https://gitlab.com/api/v4/events?page=2",
	} {
		if got := parseNextLink(in); got != expected {
			t.Errorf("parseNextLink(%q) = %q, expected %q", in, got, expected)
		}
	}
}

func TestNextPageURLIsRebased(t *testing.T) {
	a := &GitLabAdapter{conf: GitLabConfig{URL: "https://gitlab.internal:8443"}}
	// GitLab advertises its own external_url, which may not be reachable
	// from where the adapter runs.
	link := `<https://gitlab.example.com/api/v4/audit_events?id_after=5>; rel="next"`
	expected := "https://gitlab.internal:8443/api/v4/audit_events?id_after=5"
	if got := a.nextPageURL(link); got != expected {
		t.Errorf("nextPageURL() = %q, expected %q", got, expected)
	}
	if got := a.nextPageURL(""); got != "" {
		t.Errorf("nextPageURL(\"\") = %q, expected empty", got)
	}

	// An instance served from a sub-path keeps its prefix.
	a = &GitLabAdapter{conf: GitLabConfig{URL: "https://example.com/gitlab"}}
	link = `<https://gitlab.example.com/gitlab/api/v4/audit_events?id_after=5>; rel="next"`
	expected = "https://example.com/gitlab/api/v4/audit_events?id_after=5"
	if got := a.nextPageURL(link); got != expected {
		t.Errorf("nextPageURL() = %q, expected %q", got, expected)
	}
}

func TestIDKey(t *testing.T) {
	// JSON numbers decode as float64, which must not render in exponent form.
	if got := idKey(float64(1700000000)); got != "1700000000" {
		t.Errorf("idKey(float64) = %q, expected 1700000000", got)
	}
	if got := idKey("abc"); got != "abc" {
		t.Errorf("idKey(string) = %q, expected abc", got)
	}
	if got := idKey(nil); got != "" {
		t.Errorf("idKey(nil) = %q, expected empty", got)
	}
}

// A GitLab endpoint without keyset support answers 405; the adapter must
// downgrade to offset pagination and collect the window anyway.
func TestKeysetFallbackToOffset(t *testing.T) {
	var queries []url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		queries = append(queries, q)
		if q.Get("pagination") == "keyset" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte(`{"error":"Keyset pagination is not yet available for this type of request"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"id":1,"created_at":"2026-09-16T21:00:00.000Z"},
		                 {"id":2,"created_at":"2026-09-16T21:05:00.000Z"}]`))
	}))
	defer srv.Close()

	a := newTestAdapter(t, srv.URL)
	defer a.dedupe.Close()

	s := stream{eventType: eventTypeAudit, path: "/api/v4/groups/soc/audit_events", name: "group soc audit_events"}
	st := &streamState{useKeyset: true}
	since := time.Date(2026, 9, 16, 20, 0, 0, 0, time.UTC)

	newSince, n := a.fetchAuditEvents(s, since, st)

	if st.useKeyset {
		t.Error("expected the stream to downgrade to offset pagination")
	}
	if n != 2 {
		t.Errorf("fetched %d events, expected 2", n)
	}
	if len(queries) != 2 {
		t.Fatalf("made %d requests, expected 2 (keyset then offset)", len(queries))
	}
	if queries[0].Get("pagination") != "keyset" {
		t.Error("first request should have attempted keyset")
	}
	if queries[1].Get("pagination") != "" || queries[1].Get("order_by") != "" {
		t.Errorf("retry should drop the keyset params, got %v", queries[1])
	}
	if queries[1].Get("created_after") == "" {
		t.Error("retry should keep the created_after window")
	}
	// Watermark advances to the newest event, less the overlap.
	expected := time.Date(2026, 9, 16, 21, 5, 0, 0, time.UTC).Add(-overlapPeriod)
	if !newSince.Equal(expected) {
		t.Errorf("watermark = %v, expected %v", newSince, expected)
	}
}

// Once downgraded, a stream must not keep re-attempting keyset every cycle.
func TestKeysetDowngradeIsSticky(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.URL.Query().Get("pagination") == "keyset" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte(`{"error":"Keyset pagination is not yet available for this type of request"}`))
			return
		}
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	a := newTestAdapter(t, srv.URL)
	defer a.dedupe.Close()

	s := stream{eventType: eventTypeAudit, path: "/api/v4/groups/soc/audit_events", name: "soc"}
	st := &streamState{useKeyset: true}
	since := time.Now().UTC().Add(-time.Hour)

	a.fetchAuditEvents(s, since, st) // 405 then empty = 2 requests
	a.fetchAuditEvents(s, since, st) // offset only = 1 request

	if attempts != 3 {
		t.Errorf("made %d requests, expected 3 (keyset retried only once)", attempts)
	}
}

// Newest-first results that overflow a cycle must not advance the watermark
// past events that have not been read yet.
func TestDescendingTruncationDrainsBacklog(t *testing.T) {
	// Always hands back a newest-first page plus a next link, so the cycle
	// can never reach the end of the window.
	var mu sync.Mutex
	seq := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seq++
		n := seq
		mu.Unlock()
		base := time.Date(2026, 9, 16, 21, 0, 0, 0, time.UTC).Add(-time.Duration(n) * time.Minute)
		w.Header().Set("Link", "<"+r.URL.String()+"&page="+strconv.Itoa(n+1)+">; rel=\"next\"")
		fmt.Fprintf(w, `[{"id":%d,"created_at":"%s"},{"id":%d,"created_at":"%s"}]`,
			n*2, base.Format(time.RFC3339),
			n*2+1, base.Add(-30*time.Second).Format(time.RFC3339))
	}))
	defer srv.Close()

	a := newTestAdapter(t, srv.URL)
	defer a.dedupe.Close()

	s := stream{eventType: eventTypeAudit, path: "/api/v4/groups/soc/audit_events", name: "soc"}
	st := &streamState{}
	since := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	newSince, n := a.fetchAuditEvents(s, since, st)

	if n == 0 {
		t.Fatal("expected events to be shipped")
	}
	if !newSince.Equal(since) {
		t.Errorf("watermark moved to %v; it must stay at %v until the backlog drains", newSince, since)
	}
	if st.ceiling.IsZero() {
		t.Error("ceiling should be set so the next cycle reads the older remainder")
	}
	if st.pendingSince.IsZero() {
		t.Error("pendingSince should hold the high-water mark during the drain")
	}
	if !st.pendingSince.After(st.ceiling) {
		t.Errorf("pendingSince %v should be newer than ceiling %v", st.pendingSince, st.ceiling)
	}
}

func newTestAdapter(t *testing.T, baseURL string) *GitLabAdapter {
	t.Helper()
	dd, err := utils.NewLocalDeduper(time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("NewLocalDeduper(): %v", err)
	}

	opts := testClientOptions()
	// tool.go installs these before building any adapter; adapters call them
	// unguarded, so the tests have to supply them too.
	opts.DebugLog = func(string) {}
	opts.OnWarning = func(string) {}
	opts.OnError = func(error) {}
	opts.TestSinkMode = true

	uc, err := uspclient.NewClient(context.Background(), opts)
	if err != nil {
		t.Fatalf("uspclient.NewClient(): %v", err)
	}

	return &GitLabAdapter{
		conf: GitLabConfig{
			ClientOptions: opts,
			Token:         "glpat-xxxx",
			URL:           baseURL,
		},
		ctx:        context.Background(),
		doStop:     utils.NewEvent(),
		dedupe:     dd,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		uspClient:  uc,
	}
}
