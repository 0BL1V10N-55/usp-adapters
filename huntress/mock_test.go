package usp_huntress

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/refractionPOINT/go-uspclient/protocol"
	"github.com/refractionPOINT/usp-adapters/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file exercises the adapter end-to-end against a mock Huntress API,
// capturing the exact messages it ships so their content -- event type,
// timestamp and verbatim payload -- can be asserted.

// --- in-memory USP sink -----------------------------------------------------

// captureSink is an in-memory uspSink that records every shipped message.
type captureSink struct {
	mu       sync.Mutex
	messages []*protocol.DataMessage
}

func (s *captureSink) Ship(m *protocol.DataMessage, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, m)
	return nil
}

func (s *captureSink) Drain(time.Duration) error               { return nil }
func (s *captureSink) Close() ([]*protocol.DataMessage, error) { return nil, nil }

func (s *captureSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

func (s *captureSink) snapshot() []*protocol.DataMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*protocol.DataMessage, len(s.messages))
	copy(out, s.messages)
	return out
}

// --- mock Huntress API -------------------------------------------------------

// mockHuntress is an in-memory stand-in for the Huntress REST API. It honours
// the documented Signals contract: HTTP Basic auth, limit/page_token/
// sort_field/sort_direction query params, and a
// {"signals": [...], "pagination": {"next_page_token": "..."}} response
// envelope.
type mockHuntress struct {
	mu        sync.Mutex
	apiKey    string
	apiSecret string
	signals   []utils.Dict // newest-first, as the real API sorts by id desc
	requests  int
}

func newMockHuntress(apiKey, apiSecret string) *mockHuntress {
	return &mockHuntress{apiKey: apiKey, apiSecret: apiSecret}
}

// setSignals registers the full dataset the mock serves, newest-first (the
// order the real API returns for sort_field=id&sort_direction=desc).
func (m *mockHuntress) setSignals(signals []utils.Dict) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signals = signals
}

// addSignal inserts a signal at the front (newest), as a real new detection
// would appear.
func (m *mockHuntress) addSignal(signal utils.Dict) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signals = append([]utils.Dict{signal}, m.signals...)
}

func (m *mockHuntress) requestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests
}

func (m *mockHuntress) wantAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(m.apiKey+":"+m.apiSecret))
}

func (m *mockHuntress) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.requests++
		m.mu.Unlock()

		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/signals" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != m.wantAuth() {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid or missing API credentials"}`))
			return
		}

		limit := defaultLimit
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		pageToken := r.URL.Query().Get("page_token")

		m.mu.Lock()
		all := m.signals
		m.mu.Unlock()

		// The page_token is the string index (as text) to resume from,
		// mirroring the real API's opaque-but-stable cursor semantics for a
		// single, unchanging query.
		start := 0
		if pageToken != "" {
			if n, err := strconv.Atoi(pageToken); err == nil {
				start = n
			}
		}

		var page []utils.Dict
		if start < len(all) {
			end := start + limit
			if end > len(all) {
				end = len(all)
			}
			page = all[start:end]
		}
		if page == nil {
			page = []utils.Dict{}
		}

		nextToken := ""
		if start+len(page) < len(all) {
			nextToken = strconv.Itoa(start + len(page))
		}

		resp := map[string]interface{}{
			"signals": page,
			"pagination": map[string]interface{}{
				"next_page_token": nextToken,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// --- realistic record fixtures ----------------------------------------------

// realisticSignal returns a record shaped like a real Huntress Signal: the
// documented top-level fields plus a nested "details" object and "entity" /
// "organization" objects with mixed scalar types.
func realisticSignal(id int, createdAt, sigType, status string) utils.Dict {
	return utils.Dict{
		"id":         id,
		"created_at": createdAt,
		"updated_at": createdAt,
		"name":       "Firewall Disabled via Netsh",
		"type":       sigType,
		"status":     status,
		"details": utils.Dict{
			"rule_name":    "Firewall Disabled via Netsh",
			"username":     "admin22",
			"process_name": `C:\WINDOWS\system32\netsh.exe`,
			"command_line": "NetSh.exe  Advfirewall set allprofiles state off",
		},
		"entity": utils.Dict{
			"id":   72183,
			"name": "Laptop 52",
			"type": "agent",
		},
		"organization": utils.Dict{
			"id":   232,
			"name": "Huntress",
		},
	}
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// --- tests -------------------------------------------------------------------

// TestMockSignalsEndToEnd drives the adapter against the mock API and asserts
// the exact events shipped: event type, timestamp parsed from created_at,
// and the payload preserved verbatim (nested objects included).
func TestMockSignalsEndToEnd(t *testing.T) {
	const apiKey, apiSecret = "pub-key-123", "priv-key-456"

	mock := newMockHuntress(apiKey, apiSecret)
	want := []utils.Dict{
		// Newest-first, matching the mock's (and real API's default) order.
		realisticSignal(3, "2026-05-21T14:02:11Z", "Process Insights", "reported"),
		realisticSignal(2, "2026-05-21T13:50:05Z", "Antivirus", "reported"),
		realisticSignal(1, "2026-05-21T13:45:30Z", "Footholds", "closed"),
	}
	mock.setSignals(want)

	server := httptest.NewServer(mock.handler(t))
	defer server.Close()

	sink := &captureSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conf := HuntressConfig{
		ClientOptions: testClientOptions(t),
		APIKey:        apiKey,
		APISecret:     apiSecret,
		BaseURL:       server.URL,
		PollInterval:  40 * time.Millisecond,
	}
	adapter, _, err := newHuntressAdapter(ctx, conf, sink)
	require.NoError(t, err)
	defer adapter.Close()

	require.Eventually(t, func() bool { return sink.count() == 3 },
		5*time.Second, 20*time.Millisecond, "expected all 3 signals to ship")

	// Re-polling must not re-ship: the count stays at 3.
	require.Never(t, func() bool { return sink.count() != 3 },
		300*time.Millisecond, 30*time.Millisecond, "signals were re-shipped on a later poll")

	byID := map[string]*protocol.DataMessage{}
	for _, msg := range sink.snapshot() {
		assert.Equal(t, "signals", msg.EventType)
		require.NotNil(t, msg.JsonPayload)
		id := utils.Dict(msg.JsonPayload).FindOneString("id")
		if id == "" {
			if ints := utils.Dict(msg.JsonPayload).FindInt("id"); len(ints) > 0 {
				id = strconv.FormatUint(ints[0], 10)
			}
		}
		require.NotEmpty(t, id)
		byID[id] = msg
	}
	require.Len(t, byID, 3)

	for _, src := range want {
		id := strconv.Itoa(src["id"].(int))
		msg := byID[id]
		require.NotNil(t, msg, "signal %s was not shipped", id)

		ts, perr := time.Parse(time.RFC3339, src["created_at"].(string))
		require.NoError(t, perr)
		assert.Equal(t, uint64(ts.UnixMilli()), msg.TimestampMs,
			"event time should come from the signal's created_at")

		assert.JSONEq(t, mustJSON(t, src), mustJSON(t, msg.JsonPayload),
			"shipped payload must match the original Huntress signal, verbatim")
	}
}

// TestMockNewSignalShippedOnce verifies a signal that appears mid-run is
// shipped exactly once, and already-shipped signals are never re-sent.
func TestMockNewSignalShippedOnce(t *testing.T) {
	const apiKey, apiSecret = "k", "s"

	mock := newMockHuntress(apiKey, apiSecret)
	mock.setSignals([]utils.Dict{
		realisticSignal(2, "2026-05-21T10:01:00Z", "Antivirus", "reported"),
		realisticSignal(1, "2026-05-21T10:00:00Z", "Footholds", "reported"),
	})

	server := httptest.NewServer(mock.handler(t))
	defer server.Close()

	sink := &captureSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conf := HuntressConfig{
		ClientOptions: testClientOptions(t),
		APIKey:        apiKey,
		APISecret:     apiSecret,
		BaseURL:       server.URL,
		PollInterval:  30 * time.Millisecond,
	}
	adapter, _, err := newHuntressAdapter(ctx, conf, sink)
	require.NoError(t, err)
	defer adapter.Close()

	require.Eventually(t, func() bool { return sink.count() == 2 },
		5*time.Second, 20*time.Millisecond)

	// A new signal appears at the top of the feed (newest-first).
	mock.addSignal(realisticSignal(3, "2026-05-21T10:05:00Z", "SIEM", "reported"))

	require.Eventually(t, func() bool { return sink.count() == 3 },
		5*time.Second, 20*time.Millisecond, "the new signal should ship")
	require.Never(t, func() bool { return sink.count() > 3 },
		300*time.Millisecond, 30*time.Millisecond)

	shippedPerID := map[string]int{}
	for _, msg := range sink.snapshot() {
		id := utils.Dict(msg.JsonPayload).FindInt("id")[0]
		shippedPerID[strconv.FormatUint(id, 10)]++
	}
	assert.Equal(t, map[string]int{"1": 1, "2": 1, "3": 1}, shippedPerID,
		"every signal must ship exactly once")
}

// TestMockPaginationFullDataset verifies a dataset larger than one page is
// walked completely and every signal is shipped exactly once.
func TestMockPaginationFullDataset(t *testing.T) {
	const apiKey, apiSecret = "k", "s"
	const total = 250

	mock := newMockHuntress(apiKey, apiSecret)
	signals := make([]utils.Dict, total)
	for i := 0; i < total; i++ {
		// Newest-first: id total..1.
		id := total - i
		signals[i] = realisticSignal(id,
			time.Date(2026, 5, 21, 0, 0, id, 0, time.UTC).Format(time.RFC3339),
			"Antivirus", "reported")
	}
	mock.setSignals(signals)

	server := httptest.NewServer(mock.handler(t))
	defer server.Close()

	sink := &captureSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conf := HuntressConfig{
		ClientOptions: testClientOptions(t),
		APIKey:        apiKey,
		APISecret:     apiSecret,
		BaseURL:       server.URL,
		Limit:         100, // 250 records => 3 pages
		PollInterval:  50 * time.Millisecond,
	}
	adapter, _, err := newHuntressAdapter(ctx, conf, sink)
	require.NoError(t, err)
	defer adapter.Close()

	require.Eventually(t, func() bool { return sink.count() == total },
		10*time.Second, 25*time.Millisecond, "all paginated signals should ship")
	require.Never(t, func() bool { return sink.count() != total },
		300*time.Millisecond, 30*time.Millisecond)

	ids := map[uint64]bool{}
	for _, msg := range sink.snapshot() {
		ids[utils.Dict(msg.JsonPayload).FindInt("id")[0]] = true
	}
	assert.Len(t, ids, total, "every distinct signal should be shipped once")
}

// TestMockOrganizationAndTypeFilters verifies the configured organization_id/
// types/statuses filters are actually sent to the API.
func TestMockOrganizationAndTypeFilters(t *testing.T) {
	const apiKey, apiSecret = "k", "s"

	var mu sync.Mutex
	var gotOrg, gotTypes, gotStatuses string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotOrg = r.URL.Query().Get("organization_id")
		gotTypes = r.URL.Query().Get("types")
		gotStatuses = r.URL.Query().Get("statuses")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"signals":[],"pagination":{}}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conf := HuntressConfig{
		ClientOptions:  testClientOptions(t),
		APIKey:         apiKey,
		APISecret:      apiSecret,
		BaseURL:        server.URL,
		OrganizationID: 99,
		Types:          []string{"Footholds", "Ransomware Canaries"},
		Statuses:       []string{"reported"},
		PollInterval:   200 * time.Millisecond,
	}
	adapter, _, err := NewHuntressAdapter(ctx, conf)
	require.NoError(t, err)
	defer adapter.Close()

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotOrg != ""
	}, 3*time.Second, 20*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "99", gotOrg)
	assert.Equal(t, "Footholds,Ransomware Canaries", gotTypes)
	assert.Equal(t, "reported", gotStatuses)
}

// TestMockRejectsBadCredentials verifies the adapter stops, and ships
// nothing, when the mock API rejects the supplied key/secret.
func TestMockRejectsBadCredentials(t *testing.T) {
	mock := newMockHuntress("correct-key", "correct-secret")
	mock.setSignals([]utils.Dict{realisticSignal(1, "2026-05-21T10:00:00Z", "Antivirus", "reported")})

	server := httptest.NewServer(mock.handler(t))
	defer server.Close()

	sink := &captureSink{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var fatalErrors int
	var mu sync.Mutex
	opts := testClientOptions(t)
	opts.OnError = func(err error) {
		mu.Lock()
		fatalErrors++
		mu.Unlock()
		t.Logf("ERR: %v", err)
	}

	conf := HuntressConfig{
		ClientOptions: opts,
		APIKey:        "wrong-key",
		APISecret:     "wrong-secret",
		BaseURL:       server.URL,
		PollInterval:  50 * time.Millisecond,
	}
	adapter, chStopped, err := newHuntressAdapter(ctx, conf, sink)
	require.NoError(t, err)
	defer adapter.Close()

	select {
	case <-chStopped:
	case <-time.After(3 * time.Second):
		t.Fatal("adapter should stop when the API rejects credentials")
	}

	mu.Lock()
	defer mu.Unlock()
	assert.GreaterOrEqual(t, fatalErrors, 1, "a rejected credential pair must report a fatal error")
	assert.Equal(t, 0, sink.count(), "nothing should ship when authentication fails")
	assert.GreaterOrEqual(t, mock.requestCount(), 1, "the adapter should have called the API")
}
