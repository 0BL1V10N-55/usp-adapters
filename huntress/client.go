// Package usp_huntress implements a USP adapter for the Huntress REST API
// (https://api.huntress.io/v1, documented at https://api.huntress.io/docs).
//
// It polls the Signals endpoint (GET /v1/signals) -- Huntress's unified
// security-detection feed, covering Antivirus, Footholds, Process Insights,
// Managed ITDR, MDE Detections, SIEM, Ransomware Canaries, Favicon
// Detections, Attack Disruptions and App Control alerts.
//
// Events are forwarded to LimaCharlie in their original Huntress JSON form;
// the adapter does not reshape payloads.
package usp_huntress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/refractionPOINT/go-uspclient"
	"github.com/refractionPOINT/go-uspclient/protocol"
	"github.com/refractionPOINT/usp-adapters/utils"
)

const (
	defaultBaseURL = "https://api.huntress.io/v1"
	signalsPath    = "signals"

	defaultLimit = 500
	maxLimit     = 500

	defaultPollInterval = 1 * time.Minute
	defaultMaxPages     = 20
	defaultDedupeTTL    = 7 * 24 * time.Hour
	dedupeBucketWindow  = 1 * time.Hour

	defaultMaxRetryAttempts = 3
	defaultRetryBaseDelay   = 5 * time.Second
	defaultMaxRetryDelay    = 30 * time.Second

	shipTimeout = 10 * time.Second

	// eventTypeSignal is the EventType every shipped Huntress Signal is
	// tagged with.
	eventTypeSignal = "signals"

	// sortField/sortDirection pin the Signals endpoint to a deterministic,
	// newest-first order. Combined with a full re-walk of the result set
	// (bounded by MaxPages) on every poll, this makes the adapter resilient
	// to restarts without needing to persist a page_token across process
	// lifetimes: page 1 always holds the newest signals, and the deduper
	// guarantees each one still ships exactly once.
	sortField     = "id"
	sortDirection = "desc"
)

// timestampLayouts are the time formats accepted for a Signal's created_at /
// updated_at fields. Huntress documents ISO-8601 (e.g. "2025-06-26T18:57:03Z").
var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
}

// HuntressConfig is the adapter configuration.
type HuntressConfig struct {
	ClientOptions uspclient.ClientOptions `json:"client_options" yaml:"client_options"`

	// APIKey is the Huntress API public key, generated under Account > API
	// Credentials in the Huntress portal.
	APIKey string `json:"api_key" yaml:"api_key"`

	// APISecret is the API private key shown once at generation time
	// alongside APIKey.
	APISecret string `json:"api_secret" yaml:"api_secret"`

	// BaseURL overrides the API root. Defaults to https://api.huntress.io/v1.
	BaseURL string `json:"base_url" yaml:"base_url"`

	// OrganizationID, when set (> 0), scopes every request to that single
	// Huntress organization. When unset, signals for every organization the
	// API credentials can see are collected.
	OrganizationID int `json:"organization_id" yaml:"organization_id"`

	// Types, when non-empty, filters to the given Signal types (e.g.
	// "Antivirus", "Footholds", "SIEM"). See the Huntress API docs for the
	// full enumeration. Unset collects every type.
	Types []string `json:"types" yaml:"types"`

	// Statuses, when non-empty, filters to the given Signal statuses
	// ("reported", "closed"). Unset collects every status.
	Statuses []string `json:"statuses" yaml:"statuses"`

	// Limit is the number of records requested per page. Default 500 (the
	// API's own maximum).
	Limit int `json:"limit" yaml:"limit"`

	// PollInterval is the wait between polls. Default 1 minute.
	PollInterval time.Duration `json:"poll_interval" yaml:"poll_interval"`

	// MaxPages caps how many pages are fetched per poll, bounding the work of
	// a single poll. Default 20 (10,000 signals at the default limit).
	MaxPages int `json:"max_pages" yaml:"max_pages"`

	// DedupeTTL is how long a signal's identifier is remembered to suppress
	// re-shipping it on a later poll. Default 7 days.
	DedupeTTL time.Duration `json:"dedupe_ttl" yaml:"dedupe_ttl"`

	// Retry tuning for transient API failures.
	RetryBaseDelay   time.Duration `json:"retry_base_delay" yaml:"retry_base_delay"`
	MaxRetryDelay    time.Duration `json:"max_retry_delay" yaml:"max_retry_delay"`
	MaxRetryAttempts int           `json:"max_retry_attempts" yaml:"max_retry_attempts"`

	// Deduper, when set, replaces the built-in in-memory deduper. Not
	// settable through a config file; it exists as a seam for tests and for
	// embedders that want to supply a shared deduper.
	Deduper utils.Deduper `json:"-" yaml:"-"`
}

func (c *HuntressConfig) Validate() error {
	if err := c.ClientOptions.Validate(); err != nil {
		return fmt.Errorf("client_options: %v", err)
	}
	if c.APIKey == "" {
		return errors.New("missing api_key")
	}
	if c.APISecret == "" {
		return errors.New("missing api_secret")
	}

	c.BaseURL = strings.TrimSpace(c.BaseURL)
	if c.BaseURL == "" {
		c.BaseURL = defaultBaseURL
	}

	if c.OrganizationID < 0 {
		return errors.New("organization_id must not be negative")
	}

	if c.Limit <= 0 {
		c.Limit = defaultLimit
	}
	if c.Limit > maxLimit {
		c.Limit = maxLimit
	}
	if c.PollInterval <= 0 {
		c.PollInterval = defaultPollInterval
	}
	if c.MaxPages <= 0 {
		c.MaxPages = defaultMaxPages
	}
	if c.DedupeTTL <= 0 {
		c.DedupeTTL = defaultDedupeTTL
	}
	if c.RetryBaseDelay <= 0 {
		c.RetryBaseDelay = defaultRetryBaseDelay
	}
	if c.MaxRetryDelay <= 0 {
		c.MaxRetryDelay = defaultMaxRetryDelay
	}
	if c.MaxRetryAttempts <= 0 {
		c.MaxRetryAttempts = defaultMaxRetryAttempts
	}

	return nil
}

// uspSink is the subset of *uspclient.Client the adapter depends on. Expressing
// it as an interface lets tests substitute an in-memory sink for the real
// LimaCharlie client; *uspclient.Client satisfies it unchanged.
type uspSink interface {
	Ship(message *protocol.DataMessage, timeout time.Duration) error
	Drain(timeout time.Duration) error
	Close() ([]*protocol.DataMessage, error)
}

// HuntressAdapter polls the Huntress Signals endpoint and ships records to
// LimaCharlie.
type HuntressAdapter struct {
	conf        HuntressConfig
	uspClient   uspSink
	client      *HuntressClient
	deduper     utils.Deduper
	ownsDeduper bool

	chStopped chan struct{}
	wgSenders sync.WaitGroup
	doStop    *utils.Event

	closeOnce sync.Once
	closeErr  error

	ctx context.Context
}

// NewHuntressAdapter creates a Huntress adapter wired to LimaCharlie.
func NewHuntressAdapter(ctx context.Context, conf HuntressConfig) (*HuntressAdapter, chan struct{}, error) {
	return newHuntressAdapter(ctx, conf, nil)
}

// newHuntressAdapter is the implementation behind NewHuntressAdapter. When
// sink is non-nil it is used in place of a real LimaCharlie client -- the
// seam tests use to capture shipped events.
func newHuntressAdapter(ctx context.Context, conf HuntressConfig, sink uspSink) (*HuntressAdapter, chan struct{}, error) {
	if err := conf.Validate(); err != nil {
		return nil, nil, err
	}

	a := &HuntressAdapter{
		conf:   conf,
		ctx:    ctx,
		doStop: utils.NewEvent(),
	}

	// Every page is re-fetched on every poll (see the sortField/sortDirection
	// doc comment), so a deduper is required to ship each record exactly
	// once. A deduper may be supplied via the config; otherwise an in-memory
	// one is created (and owned/closed by the adapter).
	a.deduper = conf.Deduper
	if a.deduper == nil {
		window := dedupeBucketWindow
		if window > conf.DedupeTTL {
			window = conf.DedupeTTL
		}
		deduper, err := utils.NewLocalDeduper(window, conf.DedupeTTL)
		if err != nil {
			return nil, nil, fmt.Errorf("huntress: deduper: %v", err)
		}
		a.deduper = deduper
		a.ownsDeduper = true
	}

	if sink != nil {
		a.uspClient = sink
	} else {
		uspClient, err := uspclient.NewClient(ctx, conf.ClientOptions)
		if err != nil {
			if a.ownsDeduper {
				a.deduper.Close()
			}
			return nil, nil, err
		}
		a.uspClient = uspClient
	}

	a.client = NewHuntressClient(conf.BaseURL, conf.APIKey, conf.APISecret)
	a.chStopped = make(chan struct{})

	a.wgSenders.Add(1)
	go a.run()

	go func() {
		a.wgSenders.Wait()
		close(a.chStopped)
	}()

	return a, a.chStopped, nil
}

// Close stops the adapter. It is idempotent: repeated calls are no-ops and
// return the result of the first call.
func (a *HuntressAdapter) Close() error {
	a.closeOnce.Do(func() {
		a.conf.ClientOptions.DebugLog("huntress: closing")
		a.doStop.Set()
		a.wgSenders.Wait()
		err1 := a.uspClient.Drain(1 * time.Minute)
		_, err2 := a.uspClient.Close()
		a.client.Close()
		if a.ownsDeduper {
			a.deduper.Close()
		}
		if err1 != nil {
			a.closeErr = err1
		} else {
			a.closeErr = err2
		}
	})
	return a.closeErr
}

// run polls forever, until the adapter is asked to stop.
func (a *HuntressAdapter) run() {
	defer a.wgSenders.Done()
	defer a.conf.ClientOptions.DebugLog("huntress: signals polling stopped")

	isFirstRun := true
	for isFirstRun || !a.doStop.WaitFor(a.conf.PollInterval) {
		isFirstRun = false
		a.poll()
	}
}

// poll fetches one round of signals. It walks pages, newest-first, until the
// result set is exhausted (no further page token), a short page is returned,
// or MaxPages is reached.
//
// Every page is fetched on every poll; the deduper -- not an early exit -- is
// what keeps a record from being shipped more than once. This is deliberate:
// with no page_token persisted across polls (or process restarts), each poll
// re-walks from the newest signal. That is simple and restart-safe, at the
// cost of re-fetching the same recent pages repeatedly; bound the cost with
// MaxPages and Limit.
func (a *HuntressAdapter) poll() {
	nSeen := 0
	nShipped := 0
	pageToken := ""

	for page := 1; !a.doStop.IsSet(); page++ {
		if page > a.conf.MaxPages {
			a.conf.ClientOptions.OnWarning(fmt.Sprintf(
				"huntress: signals poll hit max_pages=%d; older signals are not "+
					"collected this poll -- raise max_pages or narrow the filters if "+
					"this happens often", a.conf.MaxPages))
			break
		}

		signals, nextToken, ok := a.fetchPage(pageToken)
		if !ok {
			// The error has already been reported; abandon this poll and try
			// again on the next interval.
			return
		}

		for _, sig := range signals {
			nSeen++
			if a.deduper.CheckAndAdd(a.dedupeKey(sig)) {
				continue
			}
			if !a.ship(sig) {
				return
			}
			nShipped++
		}

		if nextToken == "" || len(signals) < a.conf.Limit {
			break
		}
		pageToken = nextToken
	}

	a.conf.ClientOptions.DebugLog(fmt.Sprintf(
		"huntress: signals poll complete (seen=%d shipped=%d)", nSeen, nShipped))
}

// fetchPage requests one page of signals, retrying transient failures with
// exponential backoff. The bool result is false when the poll should be
// abandoned (any source-side error, or the adapter is stopping).
func (a *HuntressAdapter) fetchPage(pageToken string) ([]utils.Dict, string, bool) {
	query := a.buildQuery(pageToken)

	var raw []byte
	var err error
	for attempt := 0; attempt < a.conf.MaxRetryAttempts; attempt++ {
		if a.doStop.IsSet() {
			return nil, "", false
		}

		raw, err = a.client.Get(a.ctx, signalsPath, query)
		if err == nil {
			break
		}

		if !isTransientError(err) {
			var httpErr *HTTPError
			if errors.As(err, &httpErr) &&
				(httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden) {
				// Rejected credentials affect every future poll: stop the
				// whole adapter rather than burn the account's rate limit
				// (60 req/min) retrying a request that cannot succeed.
				a.conf.ClientOptions.OnError(fmt.Errorf(
					"huntress: HTTP %d -- credentials rejected; verify api_key/api_secret. Stopping the adapter.",
					httpErr.StatusCode))
				a.doStop.Set()
				return nil, "", false
			}
			// Other permanent errors (a malformed filter, an unknown
			// organization_id, ...) are reported and this poll is abandoned,
			// but the adapter keeps running: a config fix takes effect on the
			// next poll without an operator having to restart anything.
			a.conf.ClientOptions.OnWarning(fmt.Sprintf(
				"huntress: signals request failed (skipping this poll): %v", err))
			return nil, "", false
		}

		if attempt+1 >= a.conf.MaxRetryAttempts {
			break
		}
		delay := a.conf.RetryBaseDelay * time.Duration(1<<attempt)
		if delay > a.conf.MaxRetryDelay {
			delay = a.conf.MaxRetryDelay
		}
		a.conf.ClientOptions.OnWarning(fmt.Sprintf(
			"huntress: signals transient error (attempt %d/%d), retrying in %v: %v",
			attempt+1, a.conf.MaxRetryAttempts, delay, err))
		if a.doStop.WaitFor(delay) {
			return nil, "", false
		}
	}
	if err != nil {
		a.conf.ClientOptions.OnWarning(fmt.Sprintf(
			"huntress: signals request failed after %d attempts (skipping this poll): %v",
			a.conf.MaxRetryAttempts, err))
		return nil, "", false
	}

	items, nextToken, err := extractSignals(raw)
	if err != nil {
		a.conf.ClientOptions.OnWarning(fmt.Sprintf(
			"huntress: signals response parse error (skipping this poll): %v", err))
		return nil, "", false
	}
	return items, nextToken, true
}

// buildQuery assembles the query string for one page of the Signals
// endpoint.
func (a *HuntressAdapter) buildQuery(pageToken string) url.Values {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(a.conf.Limit))
	q.Set("sort_field", sortField)
	q.Set("sort_direction", sortDirection)
	if pageToken != "" {
		q.Set("page_token", pageToken)
	}
	if a.conf.OrganizationID > 0 {
		q.Set("organization_id", strconv.Itoa(a.conf.OrganizationID))
	}
	if len(a.conf.Types) > 0 {
		q.Set("types", strings.Join(a.conf.Types, ","))
	}
	if len(a.conf.Statuses) > 0 {
		q.Set("statuses", strings.Join(a.conf.Statuses, ","))
	}
	return q
}

// ship forwards a single signal to LimaCharlie. It returns false if the
// adapter should stop (an unrecoverable shipping error).
func (a *HuntressAdapter) ship(sig utils.Dict) bool {
	msg := &protocol.DataMessage{
		JsonPayload: sig,
		EventType:   eventTypeSignal,
		TimestampMs: eventTime(sig),
	}
	if err := a.uspClient.Ship(msg, shipTimeout); err != nil {
		if err == uspclient.ErrorBufferFull {
			a.conf.ClientOptions.OnWarning("huntress: stream falling behind")
			err = a.uspClient.Ship(msg, 1*time.Hour)
		}
		if err != nil {
			a.conf.ClientOptions.OnError(fmt.Errorf("huntress: Ship(): %v", err))
			a.doStop.Set()
			return false
		}
	}
	return true
}

// eventTime extracts a signal's event time from created_at, falling back to
// updated_at and then to now when neither is present or parseable.
func eventTime(sig utils.Dict) uint64 {
	for _, field := range []string{"created_at", "updated_at"} {
		if raw := sig.FindOneString(field); raw != "" {
			if t, ok := parseTimestamp(raw); ok {
				return uint64(t.UnixMilli())
			}
		}
	}
	return uint64(time.Now().UnixMilli())
}

// dedupeKey returns a stable deduplication key for a signal.
func (a *HuntressAdapter) dedupeKey(sig utils.Dict) string {
	return "signal|" + signalID(sig)
}

// signalID resolves a signal's identifier: its "id" field, or a content hash
// so deduplication still works for a record with no recognizable identifier.
func signalID(sig utils.Dict) string {
	if id := fieldAsString(sig, "id"); id != "" {
		return id
	}
	if b, err := json.Marshal(sig); err == nil {
		sum := sha256.Sum256(b)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	return ""
}

// fieldAsString reads a field as a string, accepting numeric values too
// (Huntress ids are integers).
func fieldAsString(item utils.Dict, path string) string {
	if s := item.FindOneString(path); s != "" {
		return s
	}
	if ints := item.FindInt(path); len(ints) > 0 {
		return strconv.FormatUint(ints[0], 10)
	}
	return ""
}

// extractSignals parses a Signals list response:
//
//	{"signals": [...], "pagination": {"next_page_token": "...", "next_page_url": "..."}}
//
// into a slice of records plus the token for the next page (empty when there
// is none).
func extractSignals(raw []byte) ([]utils.Dict, string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, "", nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, "", fmt.Errorf("invalid JSON object: %v", err)
	}

	signalsRaw, ok := obj["signals"]
	if !ok {
		return nil, "", fmt.Errorf("response object missing %q key (keys: %v)", "signals", keysOf(obj))
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(signalsRaw, &arr); err != nil {
		return nil, "", fmt.Errorf("%q field is not an array: %v", "signals", err)
	}

	nextToken := ""
	if paginationRaw, ok := obj["pagination"]; ok {
		var pagination struct {
			NextPageToken string `json:"next_page_token"`
		}
		if err := json.Unmarshal(paginationRaw, &pagination); err == nil {
			nextToken = pagination.NextPageToken
		}
	}

	return rawMessagesToDicts(arr), nextToken, nil
}

// rawMessagesToDicts decodes each record with utils.UnmarshalCleanJSON, which
// preserves integer precision (no float coercion) so payloads round-trip
// faithfully. A record that is not a non-empty JSON object is skipped rather
// than failing the whole page.
func rawMessagesToDicts(raw []json.RawMessage) []utils.Dict {
	items := make([]utils.Dict, 0, len(raw))
	for _, r := range raw {
		m, err := utils.UnmarshalCleanJSON(string(r))
		if err != nil || len(m) == 0 {
			continue
		}
		items = append(items, utils.Dict(m))
	}
	return items
}

func keysOf(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func parseTimestamp(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range timestampLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
