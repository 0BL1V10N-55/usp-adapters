// Package usp_beyondtrust_pra implements a USP adapter for the BeyondTrust
// Privileged Remote Access (PRA) / Remote Support Archive and Reporting APIs.
//
// Authentication uses OAuth2 client credentials. Responses from the Archive
// API are gzip-compressed; the adapter decompresses them automatically by
// checking for gzip magic bytes on the raw response body.
//
// Unlike the EPM adapter, PRA feeds are time-range based: each poll issues one
// request covering [now-window-pollInterval, now] with no offset pagination.
// Timestamps in query parameters default to Unix epoch seconds, which is what
// BeyondTrust's Archive endpoint expects.
//
// One feed is enabled by default: session_archive, which pulls the compressed
// session event log from the Archive reporting endpoint.
package usp_beyondtrust_pra

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	defaultTokenPath    = "oauth2/token"
	defaultPollInterval = 1 * time.Hour
	defaultDedupeTTL    = 7 * 24 * time.Hour
	dedupeBucketWindow  = 1 * time.Hour
	defaultWindow       = 1 * time.Hour

	defaultMaxRetryAttempts = 3
	defaultRetryBaseDelay   = 5 * time.Second
	defaultMaxRetryDelay    = 30 * time.Second
	defaultStartTimeField   = "start_time"
	defaultEndTimeField     = "end_time"
	defaultTimestampField   = "timestamp"
	defaultTimeFormat       = "epoch"

	shipTimeout = 10 * time.Second
)

var itemsArrayKeys = []string{"events", "data", "items", "sessions", "value", "results", "records"}
var commonIDFields = []string{"session_id", "sessionID", "id", "Id", "guid"}
var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
}

// ── HTTP error types ──────────────────────────────────────────────────────────

type httpError struct {
	StatusCode int
	URL        string
	Body       string
}

func (e *httpError) Error() string {
	body := e.Body
	if len(body) > 512 {
		body = body[:512] + "..."
	}
	return fmt.Sprintf("unexpected status code %d for %q: %s", e.StatusCode, e.URL, body)
}

func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	var he *httpError
	if errors.As(err, &he) {
		return he.StatusCode >= 500 || he.StatusCode == http.StatusTooManyRequests
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return strings.Contains(err.Error(), "failed to execute request")
}

// ── OAuth2 HTTP client with gzip decompression ────────────────────────────────

type praClient struct {
	baseURL      string
	clientID     string
	clientSecret string
	tokenPath    string
	httpClient   *http.Client

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

func newPRAClient(baseURL, clientID, clientSecret, tokenPath string) *praClient {
	return &praClient{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenPath:    tokenPath,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				Dial: (&net.Dialer{Timeout: 10 * time.Second}).Dial,
			},
		},
	}
}

func (c *praClient) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}
	return c.refreshToken(ctx)
}

func (c *praClient) refreshToken(ctx context.Context) error {
	tokenURL := c.baseURL + "/" + strings.TrimPrefix(c.tokenPath, "/")
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("beyondtrust_pra: token request create: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("beyondtrust_pra: token request: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return &httpError{StatusCode: resp.StatusCode, URL: tokenURL, Body: string(respBody)}
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return fmt.Errorf("beyondtrust_pra: token parse: %v", err)
	}
	if tokenResp.AccessToken == "" {
		return errors.New("beyondtrust_pra: missing access_token in token response")
	}

	expiry := tokenResp.ExpiresIn
	if expiry <= 0 {
		expiry = 3600
	}
	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(expiry-60) * time.Second)
	return nil
}

// get issues an authenticated GET and decompresses the response if it is
// gzip-encoded (detected via magic bytes, handling both transparent transport
// decompression and Content-Type: application/gzip responses).
func (c *praClient) get(ctx context.Context, path string, params url.Values) ([]byte, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	c.mu.Lock()
	token := c.accessToken
	c.mu.Unlock()

	fullURL := c.baseURL + "/" + strings.TrimPrefix(path, "/")
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request %q: %v", fullURL, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request %q: %v", fullURL, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response %q: %v", fullURL, err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		c.mu.Lock()
		c.accessToken = ""
		c.mu.Unlock()
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{StatusCode: resp.StatusCode, URL: fullURL, Body: string(raw)}
	}

	return decompressIfGzip(raw), nil
}

// decompressIfGzip decompresses raw if it begins with gzip magic bytes (0x1f 0x8b).
// If decompression fails the original bytes are returned unchanged.
func decompressIfGzip(raw []byte) []byte {
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		return raw
	}
	gr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return raw
	}
	defer gr.Close()
	decompressed, err := io.ReadAll(gr)
	if err != nil {
		return raw
	}
	return decompressed
}

func (c *praClient) close() {
	c.httpClient.CloseIdleConnections()
}

// ── Feed and config types ─────────────────────────────────────────────────────

// PRAFeed describes a single BeyondTrust PRA / Remote Support API endpoint to
// poll. Each poll issues one request covering the rolling time window; there is
// no offset pagination because the Archive endpoint returns all matching events
// for the requested range in a single (compressed) response.
type PRAFeed struct {
	Name           string            `json:"name" yaml:"name"`
	Path           string            `json:"path" yaml:"path"`
	TimestampField string            `json:"timestamp_field" yaml:"timestamp_field"`
	IDField        string            `json:"id_field" yaml:"id_field"`
	Window         time.Duration     `json:"window" yaml:"window"`
	StartTimeField string            `json:"start_time_field" yaml:"start_time_field"`
	EndTimeField   string            `json:"end_time_field" yaml:"end_time_field"`
	ItemsPath      string            `json:"items_path" yaml:"items_path"`
	ExtraParams    map[string]string `json:"extra_params" yaml:"extra_params"`

	// TimeFormat controls how the rolling-window timestamps are encoded into
	// query parameters. "epoch" (default) sends Unix epoch seconds, which is
	// what the BeyondTrust Archive API expects. "rfc3339" sends ISO 8601.
	TimeFormat string `json:"time_format" yaml:"time_format"`
}

// PRAConfig is the adapter configuration.
type PRAConfig struct {
	ClientOptions uspclient.ClientOptions `json:"client_options" yaml:"client_options"`

	// BaseURL is the PRA / Remote Support server URL, e.g. "https://pra.company.com".
	BaseURL string `json:"base_url" yaml:"base_url"`

	// ClientID and ClientSecret are the OAuth2 credentials for the API account.
	ClientID     string `json:"client_id" yaml:"client_id"`
	ClientSecret string `json:"client_secret" yaml:"client_secret"`

	// TokenPath is the OAuth2 token endpoint path relative to BaseURL.
	// Default: "oauth2/token".
	TokenPath string `json:"token_path" yaml:"token_path"`

	// Feeds is the list of PRA endpoints to poll.
	// Default: one session_archive feed against the Archive reporting endpoint.
	Feeds []PRAFeed `json:"feeds" yaml:"feeds"`

	// PollInterval is the wait between polls of a feed. Default: 1 hour.
	// The Archive API stores up to 7 days of history; a 1-hour interval with
	// a 1-hour window ensures no gaps while keeping request volume low.
	PollInterval time.Duration `json:"poll_interval" yaml:"poll_interval"`

	// DedupeTTL is how long a record ID is remembered to suppress re-shipping.
	// Default: 7 days (matches the Archive API's retention window).
	DedupeTTL time.Duration `json:"dedupe_ttl" yaml:"dedupe_ttl"`

	RetryBaseDelay   time.Duration `json:"retry_base_delay" yaml:"retry_base_delay"`
	MaxRetryDelay    time.Duration `json:"max_retry_delay" yaml:"max_retry_delay"`
	MaxRetryAttempts int           `json:"max_retry_attempts" yaml:"max_retry_attempts"`

	Deduper utils.Deduper `json:"-" yaml:"-"`
}

// defaultFeeds returns the default PRA feed: session_archive, which queries
// the BeyondTrust Archive reporting endpoint for all session events in the
// rolling time window.
func defaultFeeds() []PRAFeed {
	return []PRAFeed{
		{
			Name:           "session_archive",
			Path:           "api/reporting",
			TimestampField: defaultTimestampField,
			IDField:        "session_id",
			Window:         defaultWindow,
			StartTimeField: defaultStartTimeField,
			EndTimeField:   defaultEndTimeField,
			TimeFormat:     defaultTimeFormat,
			ExtraParams:    map[string]string{"generate_report": "Archive"},
		},
	}
}

func (c *PRAConfig) Validate() error {
	if err := c.ClientOptions.Validate(); err != nil {
		return fmt.Errorf("client_options: %v", err)
	}
	if c.BaseURL == "" {
		return errors.New("missing base_url")
	}
	if c.ClientID == "" {
		return errors.New("missing client_id")
	}
	if c.ClientSecret == "" {
		return errors.New("missing client_secret")
	}
	if c.TokenPath == "" {
		c.TokenPath = defaultTokenPath
	}
	if c.PollInterval <= 0 {
		c.PollInterval = defaultPollInterval
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
	if len(c.Feeds) == 0 {
		c.Feeds = defaultFeeds()
	}
	seen := make(map[string]struct{}, len(c.Feeds))
	for i := range c.Feeds {
		f := &c.Feeds[i]
		f.Name = strings.TrimSpace(f.Name)
		f.Path = strings.TrimSpace(strings.TrimPrefix(f.Path, "/"))
		if f.Path == "" {
			return fmt.Errorf("feed %d: missing path", i)
		}
		if f.Name == "" {
			return fmt.Errorf("feed %q: missing name", f.Path)
		}
		if _, ok := seen[f.Name]; ok {
			return fmt.Errorf("feed %q: duplicate name", f.Name)
		}
		seen[f.Name] = struct{}{}
		if f.TimestampField == "" {
			f.TimestampField = defaultTimestampField
		}
		if f.Window <= 0 {
			f.Window = defaultWindow
		}
		if f.StartTimeField == "" {
			f.StartTimeField = defaultStartTimeField
		}
		if f.EndTimeField == "" {
			f.EndTimeField = defaultEndTimeField
		}
		if f.TimeFormat == "" {
			f.TimeFormat = defaultTimeFormat
		}
	}
	return nil
}

// ── Adapter ───────────────────────────────────────────────────────────────────

type uspSink interface {
	Ship(message *protocol.DataMessage, timeout time.Duration) error
	Drain(timeout time.Duration) error
	Close() ([]*protocol.DataMessage, error)
}

// PRAAdapter polls one or more BeyondTrust PRA feeds and ships their events
// to LimaCharlie.
type PRAAdapter struct {
	conf        PRAConfig
	uspClient   uspSink
	client      *praClient
	deduper     utils.Deduper
	ownsDeduper bool

	chStopped chan struct{}
	wgSenders sync.WaitGroup
	doStop    *utils.Event

	closeOnce sync.Once
	closeErr  error

	ctx context.Context
}

// NewPRAAdapter creates a PRA adapter wired to LimaCharlie.
func NewPRAAdapter(ctx context.Context, conf PRAConfig) (*PRAAdapter, chan struct{}, error) {
	return newPRAAdapter(ctx, conf, nil)
}

func newPRAAdapter(ctx context.Context, conf PRAConfig, sink uspSink) (*PRAAdapter, chan struct{}, error) {
	if err := conf.Validate(); err != nil {
		return nil, nil, err
	}

	a := &PRAAdapter{
		conf:   conf,
		ctx:    ctx,
		doStop: utils.NewEvent(),
	}

	a.deduper = conf.Deduper
	if a.deduper == nil {
		window := dedupeBucketWindow
		if window > conf.DedupeTTL {
			window = conf.DedupeTTL
		}
		d, err := utils.NewLocalDeduper(window, conf.DedupeTTL)
		if err != nil {
			return nil, nil, fmt.Errorf("beyondtrust_pra: deduper: %v", err)
		}
		a.deduper = d
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

	a.client = newPRAClient(conf.BaseURL, conf.ClientID, conf.ClientSecret, conf.TokenPath)
	a.chStopped = make(chan struct{})

	for _, feed := range conf.Feeds {
		a.conf.ClientOptions.DebugLog(fmt.Sprintf("beyondtrust_pra: starting feed %q -> %s", feed.Name, feed.Path))
		a.wgSenders.Add(1)
		go a.runFeed(feed)
	}

	go func() {
		a.wgSenders.Wait()
		close(a.chStopped)
	}()

	return a, a.chStopped, nil
}

func (a *PRAAdapter) Close() error {
	a.closeOnce.Do(func() {
		a.conf.ClientOptions.DebugLog("beyondtrust_pra: closing")
		a.doStop.Set()
		a.wgSenders.Wait()
		err1 := a.uspClient.Drain(1 * time.Minute)
		_, err2 := a.uspClient.Close()
		a.client.close()
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

func (a *PRAAdapter) runFeed(feed PRAFeed) {
	defer a.wgSenders.Done()
	defer a.conf.ClientOptions.DebugLog(fmt.Sprintf("beyondtrust_pra: feed %q stopped", feed.Name))

	isFirstRun := true
	for isFirstRun || !a.doStop.WaitFor(a.conf.PollInterval) {
		isFirstRun = false
		a.pollFeed(feed)
	}
}

// pollFeed issues a single time-range request for the feed. The Archive API
// returns all matching events in the window as one (compressed) response, so
// there is no pagination loop.
func (a *PRAAdapter) pollFeed(feed PRAFeed) {
	if a.doStop.IsSet() {
		return
	}

	params := a.buildQueryParams(feed)

	var raw []byte
	var err error
	for attempt := 0; attempt < a.conf.MaxRetryAttempts; attempt++ {
		if a.doStop.IsSet() {
			return
		}
		raw, err = a.client.get(a.ctx, feed.Path, params)
		if err == nil {
			break
		}
		if !isTransientError(err) {
			a.conf.ClientOptions.OnError(fmt.Errorf("beyondtrust_pra: feed %q request failed: %v", feed.Name, err))
			var he *httpError
			if errors.As(err, &he) && (he.StatusCode == http.StatusUnauthorized || he.StatusCode == http.StatusForbidden) {
				a.conf.ClientOptions.OnError(fmt.Errorf(
					"beyondtrust_pra: HTTP %d — verify client_id, client_secret, and base_url",
					he.StatusCode))
				a.doStop.Set()
			}
			return
		}
		if attempt+1 >= a.conf.MaxRetryAttempts {
			break
		}
		delay := a.conf.RetryBaseDelay * time.Duration(1<<attempt)
		if delay > a.conf.MaxRetryDelay {
			delay = a.conf.MaxRetryDelay
		}
		a.conf.ClientOptions.OnWarning(fmt.Sprintf(
			"beyondtrust_pra: feed %q transient error (attempt %d/%d), retrying in %v: %v",
			feed.Name, attempt+1, a.conf.MaxRetryAttempts, delay, err))
		if a.doStop.WaitFor(delay) {
			return
		}
	}
	if err != nil {
		a.conf.ClientOptions.OnError(fmt.Errorf(
			"beyondtrust_pra: feed %q failed after %d attempts: %v", feed.Name, a.conf.MaxRetryAttempts, err))
		return
	}

	items, err := extractItems(raw, feed.ItemsPath)
	if err != nil {
		a.conf.ClientOptions.OnError(fmt.Errorf("beyondtrust_pra: feed %q parse error: %v", feed.Name, err))
		return
	}

	nShipped := 0
	for _, item := range items {
		if a.deduper.CheckAndAdd(feed.Name + "|" + recordID(feed.IDField, item)) {
			continue
		}
		if !a.ship(feed, item) {
			return
		}
		nShipped++
	}
	a.conf.ClientOptions.DebugLog(fmt.Sprintf(
		"beyondtrust_pra: feed %q poll complete (seen=%d shipped=%d)", feed.Name, len(items), nShipped))
}

func (a *PRAAdapter) buildQueryParams(feed PRAFeed) url.Values {
	params := url.Values{}
	for k, v := range feed.ExtraParams {
		params.Set(k, v)
	}
	end := time.Now().UTC()
	start := end.Add(-feed.Window - a.conf.PollInterval)
	params.Set(feed.StartTimeField, formatTime(start, feed.TimeFormat))
	params.Set(feed.EndTimeField, formatTime(end, feed.TimeFormat))
	return params
}

func formatTime(t time.Time, format string) string {
	if format == "epoch" {
		return strconv.FormatInt(t.Unix(), 10)
	}
	return t.Format(time.RFC3339)
}

func (a *PRAAdapter) ship(feed PRAFeed, item utils.Dict) bool {
	msg := &protocol.DataMessage{
		JsonPayload: item,
		EventType:   feed.Name,
		TimestampMs: a.eventTime(feed, item),
	}
	if err := a.uspClient.Ship(msg, shipTimeout); err != nil {
		if err == uspclient.ErrorBufferFull {
			a.conf.ClientOptions.OnWarning("beyondtrust_pra: stream falling behind")
			err = a.uspClient.Ship(msg, 1*time.Hour)
		}
		if err != nil {
			a.conf.ClientOptions.OnError(fmt.Errorf("beyondtrust_pra: Ship(): %v", err))
			a.doStop.Set()
			return false
		}
	}
	return true
}

func (a *PRAAdapter) eventTime(feed PRAFeed, item utils.Dict) uint64 {
	if raw := item.FindOneString(feed.TimestampField); raw != "" {
		if t, ok := parseTimestamp(raw); ok {
			return uint64(t.UnixMilli())
		}
		// Also try epoch seconds (PRA may return numeric timestamps)
		if ints := item.FindInt(feed.TimestampField); len(ints) > 0 {
			return ints[0] * 1000 // epoch seconds → milliseconds
		}
	}
	return uint64(time.Now().UnixMilli())
}

// ── Shared helpers ────────────────────────────────────────────────────────────

func recordID(idField string, item utils.Dict) string {
	if idField != "" {
		if id := fieldAsString(item, idField); id != "" {
			return id
		}
	}
	for _, k := range commonIDFields {
		if id := fieldAsString(item, k); id != "" {
			return id
		}
	}
	if b, err := json.Marshal(item); err == nil {
		sum := sha256.Sum256(b)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	return ""
}

func fieldAsString(item utils.Dict, path string) string {
	if s := item.FindOneString(path); s != "" {
		return s
	}
	if ints := item.FindInt(path); len(ints) > 0 {
		return strconv.FormatUint(ints[0], 10)
	}
	return ""
}

func extractItems(raw []byte, itemsPath string) ([]utils.Dict, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	switch trimmed[0] {
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %v", err)
		}
		return rawMessagesToDicts(arr), nil
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
			return nil, fmt.Errorf("invalid JSON object: %v", err)
		}
		var arrRaw json.RawMessage
		if itemsPath != "" {
			arrRaw = obj[itemsPath]
			if arrRaw == nil {
				return nil, fmt.Errorf("items_path %q not present in response (keys: %v)", itemsPath, keysOf(obj))
			}
		} else {
			for _, k := range itemsArrayKeys {
				if v, ok := obj[k]; ok {
					arrRaw = v
					break
				}
			}
			if arrRaw == nil {
				return nil, fmt.Errorf("could not locate records array in response (keys: %v); set items_path", keysOf(obj))
			}
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(arrRaw, &arr); err != nil {
			return nil, fmt.Errorf("response field is not a JSON array: %v", err)
		}
		return rawMessagesToDicts(arr), nil
	default:
		return nil, errors.New("response is neither a JSON array nor a JSON object")
	}
}

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
	for _, layout := range timestampLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
