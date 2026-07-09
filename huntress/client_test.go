package usp_huntress

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/refractionPOINT/go-uspclient"
	"github.com/refractionPOINT/usp-adapters/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testClientOptions returns ClientOptions wired for a sink (no real
// LimaCharlie connection) with the logging callbacks pointed at the test log.
func testClientOptions(t *testing.T) uspclient.ClientOptions {
	t.Helper()
	return uspclient.ClientOptions{
		Identity: uspclient.Identity{
			Oid:             "11111111-1111-1111-1111-111111111111",
			InstallationKey: "test-installation-key",
		},
		Platform:     "json",
		TestSinkMode: true,
		DebugLog:     func(msg string) { t.Logf("DBG: %s", msg) },
		OnWarning:    func(msg string) { t.Logf("WRN: %s", msg) },
		OnError:      func(err error) { t.Logf("ERR: %v", err) },
	}
}

// signalItem builds a minimal Huntress-Signal-shaped record.
func signalItem(id int, createdAt string) map[string]interface{} {
	return map[string]interface{}{
		"id":         id,
		"created_at": createdAt,
		"updated_at": createdAt,
		"name":       "Firewall Disabled via Netsh",
		"type":       "Process Insights",
		"status":     "reported",
	}
}

// countingDeduper wraps a Deduper and records, per key, how many times the
// key was reported as new (CheckAndAdd returned false). The adapter ships a
// record exactly when its key is new, so a count above 1 means a record was
// shipped more than once -- a dedup failure.
type countingDeduper struct {
	inner utils.Deduper
	mu    sync.Mutex
	new   map[string]int
}

func newCountingDeduper(t *testing.T) *countingDeduper {
	t.Helper()
	inner, err := utils.NewLocalDeduper(time.Hour, time.Hour)
	require.NoError(t, err)
	return &countingDeduper{inner: inner, new: map[string]int{}}
}

func (d *countingDeduper) CheckAndAdd(key string) bool {
	exists := d.inner.CheckAndAdd(key)
	if !exists {
		d.mu.Lock()
		d.new[key]++
		d.mu.Unlock()
	}
	return exists
}

func (d *countingDeduper) Close() { d.inner.Close() }

func (d *countingDeduper) newCount(key string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.new[key]
}

func (d *countingDeduper) distinctKeys() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.new)
}

// --- unit tests --------------------------------------------------------------

func TestExtractSignals(t *testing.T) {
	t.Run("parses signals and next_page_token", func(t *testing.T) {
		items, next, err := extractSignals([]byte(
			`{"signals":[{"id":1},{"id":2}],"pagination":{"next_page_token":"tok-2"}}`))
		require.NoError(t, err)
		require.Len(t, items, 2)
		assert.Equal(t, "tok-2", next)
	})

	t.Run("last page has no next_page_token", func(t *testing.T) {
		items, next, err := extractSignals([]byte(`{"signals":[{"id":1}],"pagination":{}}`))
		require.NoError(t, err)
		require.Len(t, items, 1)
		assert.Empty(t, next)
	})

	t.Run("missing pagination key still parses signals", func(t *testing.T) {
		items, next, err := extractSignals([]byte(`{"signals":[{"id":1}]}`))
		require.NoError(t, err)
		require.Len(t, items, 1)
		assert.Empty(t, next)
	})

	t.Run("empty body yields no items", func(t *testing.T) {
		items, next, err := extractSignals([]byte("  "))
		require.NoError(t, err)
		assert.Empty(t, items)
		assert.Empty(t, next)
	})

	t.Run("missing signals key errors", func(t *testing.T) {
		_, _, err := extractSignals([]byte(`{"pagination":{}}`))
		assert.Error(t, err)
	})

	t.Run("non-json errors", func(t *testing.T) {
		_, _, err := extractSignals([]byte(`not json`))
		assert.Error(t, err)
	})

	t.Run("large integer ids keep precision", func(t *testing.T) {
		items, _, err := extractSignals([]byte(`{"signals":[{"id":123456789012345678}]}`))
		require.NoError(t, err)
		require.Len(t, items, 1)
		v, ok := items[0].GetInt("id")
		require.True(t, ok)
		assert.Equal(t, uint64(123456789012345678), v)
	})

	t.Run("non-object records are skipped, valid ones kept", func(t *testing.T) {
		items, _, err := extractSignals([]byte(`{"signals":[{"id":1},"junk",123,null,{"id":2}]}`))
		require.NoError(t, err)
		require.Len(t, items, 2)
	})
}

func TestSignalID(t *testing.T) {
	t.Run("uses the id field", func(t *testing.T) {
		assert.Equal(t, "42", signalID(utils.Dict{"id": uint64(42)}))
	})

	t.Run("accepts an id of zero", func(t *testing.T) {
		// A real id of 0 must not be mistaken for "absent".
		assert.Equal(t, "0", signalID(utils.Dict{"id": uint64(0)}))
	})

	t.Run("content hash fallback is stable and distinct", func(t *testing.T) {
		a1 := signalID(utils.Dict{"foo": "bar"})
		a2 := signalID(utils.Dict{"foo": "bar"})
		b := signalID(utils.Dict{"foo": "baz"})
		assert.Equal(t, a1, a2)
		assert.NotEqual(t, a1, b)
		assert.Contains(t, a1, "sha256:")
	})
}

func TestEventTime(t *testing.T) {
	t.Run("uses created_at", func(t *testing.T) {
		ts := eventTime(utils.Dict{"created_at": "2025-06-26T18:57:03Z", "updated_at": "2025-06-27T00:00:00Z"})
		want, _ := time.Parse(time.RFC3339, "2025-06-26T18:57:03Z")
		assert.Equal(t, uint64(want.UnixMilli()), ts)
	})

	t.Run("falls back to updated_at", func(t *testing.T) {
		ts := eventTime(utils.Dict{"updated_at": "2025-06-27T00:00:00Z"})
		want, _ := time.Parse(time.RFC3339, "2025-06-27T00:00:00Z")
		assert.Equal(t, uint64(want.UnixMilli()), ts)
	})

	t.Run("falls back to now when absent", func(t *testing.T) {
		before := time.Now().UnixMilli()
		ts := eventTime(utils.Dict{})
		after := time.Now().UnixMilli()
		assert.GreaterOrEqual(t, int64(ts), before)
		assert.LessOrEqual(t, int64(ts), after)
	})
}

func TestIsTransientError(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		isTransient bool
	}{
		{"500", &HTTPError{StatusCode: 500}, true},
		{"503", &HTTPError{StatusCode: 503}, true},
		{"429", &HTTPError{StatusCode: 429}, true},
		{"401", &HTTPError{StatusCode: 401}, false},
		{"403", &HTTPError{StatusCode: 403}, false},
		{"404", &HTTPError{StatusCode: 404}, false},
		{"400", &HTTPError{StatusCode: 400}, false},
		{"network", fmt.Errorf("failed to execute request %q: connection refused", "x"), true},
		{"context canceled", context.Canceled, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.isTransient, isTransientError(c.err))
		})
	}
}

func TestValidate(t *testing.T) {
	t.Run("requires api_key", func(t *testing.T) {
		c := HuntressConfig{ClientOptions: testClientOptions(t), APISecret: "s"}
		assert.Error(t, c.Validate())
	})

	t.Run("requires api_secret", func(t *testing.T) {
		c := HuntressConfig{ClientOptions: testClientOptions(t), APIKey: "k"}
		assert.Error(t, c.Validate())
	})

	t.Run("rejects a negative organization_id", func(t *testing.T) {
		c := HuntressConfig{ClientOptions: testClientOptions(t), APIKey: "k", APISecret: "s", OrganizationID: -1}
		assert.Error(t, c.Validate())
	})

	t.Run("applies defaults", func(t *testing.T) {
		c := HuntressConfig{ClientOptions: testClientOptions(t), APIKey: "k", APISecret: "s"}
		require.NoError(t, c.Validate())
		assert.Equal(t, defaultBaseURL, c.BaseURL)
		assert.Equal(t, defaultLimit, c.Limit)
		assert.Equal(t, defaultPollInterval, c.PollInterval)
		assert.Equal(t, defaultMaxPages, c.MaxPages)
		assert.Equal(t, defaultDedupeTTL, c.DedupeTTL)
		assert.Equal(t, defaultMaxRetryAttempts, c.MaxRetryAttempts)
	})

	t.Run("clamps limit to the API maximum", func(t *testing.T) {
		c := HuntressConfig{ClientOptions: testClientOptions(t), APIKey: "k", APISecret: "s", Limit: 10000}
		require.NoError(t, c.Validate())
		assert.Equal(t, maxLimit, c.Limit)
	})
}

func TestBuildQuery(t *testing.T) {
	t.Run("base query", func(t *testing.T) {
		a := &HuntressAdapter{conf: HuntressConfig{Limit: 250}}
		q := a.buildQuery("")
		assert.Equal(t, "250", q.Get("limit"))
		assert.Equal(t, sortField, q.Get("sort_field"))
		assert.Equal(t, sortDirection, q.Get("sort_direction"))
		assert.Empty(t, q.Get("page_token"))
		assert.Empty(t, q.Get("organization_id"))
	})

	t.Run("includes page_token when set", func(t *testing.T) {
		a := &HuntressAdapter{conf: HuntressConfig{Limit: 250}}
		q := a.buildQuery("cursor-abc")
		assert.Equal(t, "cursor-abc", q.Get("page_token"))
	})

	t.Run("includes optional filters", func(t *testing.T) {
		a := &HuntressAdapter{conf: HuntressConfig{
			Limit:          250,
			OrganizationID: 42,
			Types:          []string{"Antivirus", "Footholds"},
			Statuses:       []string{"reported"},
		}}
		q := a.buildQuery("")
		assert.Equal(t, "42", q.Get("organization_id"))
		assert.Equal(t, "Antivirus,Footholds", q.Get("types"))
		assert.Equal(t, "reported", q.Get("statuses"))
	})
}

func TestParseTimestamp(t *testing.T) {
	cases := []string{
		"2025-06-26T18:57:03Z",
		"2025-06-26T18:57:03.123456Z",
		"2025-06-26T18:57:03",
	}
	for _, c := range cases {
		_, ok := parseTimestamp(c)
		assert.True(t, ok, "expected %q to parse", c)
	}
	_, ok := parseTimestamp("not a date")
	assert.False(t, ok)
}

// --- integration tests -------------------------------------------------------

// TestSignalsRequest verifies the adapter targets the signals endpoint with
// the expected method, auth header and query parameters.
func TestSignalsRequest(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotAuth, gotMethod string
	var gotQuery url.Values

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.Query()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"signals":[],"pagination":{}}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conf := HuntressConfig{
		ClientOptions:  testClientOptions(t),
		APIKey:         "pubkey",
		APISecret:      "privkey",
		BaseURL:        server.URL,
		OrganizationID: 7,
		PollInterval:   200 * time.Millisecond,
	}
	adapter, chStopped, err := NewHuntressAdapter(ctx, conf)
	require.NoError(t, err)
	defer adapter.Close()

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotPath != ""
	}, 3*time.Second, 20*time.Millisecond, "adapter never called the API")

	select {
	case <-chStopped:
		t.Fatal("adapter stopped unexpectedly")
	default:
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, http.MethodGet, gotMethod)
	assert.Equal(t, "/signals", gotPath)

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("pubkey:privkey"))
	assert.Equal(t, wantAuth, gotAuth)
	assert.Equal(t, "7", gotQuery.Get("organization_id"))
	assert.Equal(t, strconv.Itoa(defaultLimit), gotQuery.Get("limit"))
	assert.Equal(t, "id", gotQuery.Get("sort_field"))
	assert.Equal(t, "desc", gotQuery.Get("sort_direction"))
}

// TestMaxPagesCap verifies a poll stops paginating at max_pages rather than
// walking an unbounded result set.
func TestMaxPagesCap(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	var idCounter atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("page_token")
		mu.Lock()
		hits[token]++
		mu.Unlock()

		// Always return a full page of brand-new records with a fresh
		// next_page_token, so pagination would never terminate on its own.
		nextToken := fmt.Sprintf("tok-%d", idCounter.Add(1))
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"signals":[%s,%s],"pagination":{"next_page_token":%q}}`,
			signalJSON(int(idCounter.Add(1)), "2025-06-26T18:57:03Z"),
			signalJSON(int(idCounter.Add(1)), "2025-06-26T18:57:03Z"),
			nextToken)
	}))
	defer server.Close()

	var maxPagesWarned atomic.Bool
	opts := testClientOptions(t)
	opts.OnWarning = func(msg string) {
		t.Logf("WRN: %s", msg)
		if containsMaxPages(msg) {
			maxPagesWarned.Store(true)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conf := HuntressConfig{
		ClientOptions: opts,
		APIKey:        "k",
		APISecret:     "s",
		BaseURL:       server.URL,
		Limit:         2,
		MaxPages:      3,
		PollInterval:  1 * time.Hour, // only the initial poll runs during the test
	}
	adapter, _, err := NewHuntressAdapter(ctx, conf)
	require.NoError(t, err)
	defer adapter.Close()

	require.Eventually(t, maxPagesWarned.Load, 5*time.Second, 20*time.Millisecond,
		"adapter should warn when max_pages is reached")

	mu.Lock()
	defer mu.Unlock()
	total := 0
	for _, n := range hits {
		total += n
	}
	assert.Equal(t, 3, total, "exactly max_pages=3 requests should be made")
}

// TestTransientErrorRetry verifies the adapter retries 5xx responses rather
// than terminating.
func TestTransientErrorRetry(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCount.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"transient"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"signals":[],"pagination":{}}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conf := HuntressConfig{
		ClientOptions:  testClientOptions(t),
		APIKey:         "k",
		APISecret:      "s",
		BaseURL:        server.URL,
		PollInterval:   100 * time.Millisecond,
		RetryBaseDelay: 20 * time.Millisecond,
		MaxRetryDelay:  40 * time.Millisecond,
	}
	adapter, chStopped, err := NewHuntressAdapter(ctx, conf)
	require.NoError(t, err)
	defer adapter.Close()

	time.Sleep(500 * time.Millisecond)

	select {
	case <-chStopped:
		t.Fatal("adapter stopped on a transient error - it should have retried")
	default:
	}
	assert.GreaterOrEqual(t, requestCount.Load(), int32(3), "expected retries then success")
}

// TestBadAuthStopsAdapter verifies a rejected credential pair (401/403) is
// fatal: the adapter stops itself and ships nothing further.
func TestBadAuthStopsAdapter(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				w.Write([]byte(`{"error":"denied"}`))
			}))
			defer server.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			var fatalErrors atomic.Int32
			opts := testClientOptions(t)
			opts.OnError = func(err error) { fatalErrors.Add(1); t.Logf("ERR: %v", err) }

			conf := HuntressConfig{
				ClientOptions: opts,
				APIKey:        "bad-key",
				APISecret:     "bad-secret",
				BaseURL:       server.URL,
				PollInterval:  50 * time.Millisecond,
			}
			adapter, chStopped, err := NewHuntressAdapter(ctx, conf)
			require.NoError(t, err)
			defer adapter.Close()

			select {
			case <-chStopped:
			case <-time.After(3 * time.Second):
				t.Fatalf("adapter should have stopped on HTTP %d", status)
			}
			assert.GreaterOrEqual(t, fatalErrors.Load(), int32(1))
		})
	}
}

// --- small helpers used only by the tests in this file ----------------------

func signalJSON(id int, createdAt string) string {
	return fmt.Sprintf(`{"id":%d,"created_at":%q}`, id, createdAt)
}

func containsMaxPages(msg string) bool {
	return strings.Contains(msg, "max_pages")
}
