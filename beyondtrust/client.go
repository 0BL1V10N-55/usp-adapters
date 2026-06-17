// Package usp_beyondtrust implements a USP adapter for the BeyondTrust
// Endpoint Privilege Management (EPM) Management API.
//
// The adapter authenticates with OAuth2 client credentials, then polls one or
// more configurable "feeds" — each feed maps to a single API endpoint. Two
// feeds are enabled by default: EPM Client Events (endpoint activity such as
// process executions and privilege elevations) and Activity Audit Events
// (administrator actions taken in the EPM web interface).
//
// Events are forwarded to LimaCharlie in their original BeyondTrust JSON form;
// the adapter does not reshape payloads.
//
// Supporting a new BeyondTrust API endpoint requires only a configuration
// change — no code modification.
package usp_beyondtrust

import (
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

// ── HTTP client ───────────────────────────────────────────────────────────────

// HTTPError represents a non-2xx response from the BeyondTrust API.
type HTTPError struct {
	StatusCode int
	URL        string
	Body       string
}

func (e *HTTPError) Error() string {
	body := e.Body
	if len(body) > 512 {
		body = body[:512] + "..."
	}
	return fmt.Sprintf("unexpected status code %d for %q: %s", e.StatusCode, e.URL, body)
}

// isTransientError reports whether an error is worth retrying.
//
// Transient: HTTP 5xx, HTTP 429, network errors.
// Permanent: HTTP 4xx (other than 429), context cancellation.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode >= 500 || httpErr.StatusCode == http.StatusTooManyRequests
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return strings.Contains(err.Error(), "failed to execute request")
}

// beyondTrustClient is a thin OAuth2-authenticated HTTP wrapper around the
// BeyondTrust EPM Management API. It caches the access token and refreshes it
// automatically before expiry.
type beyondTrustClient struct {
	baseURL      string
	clientID     string
	clientSecret string
	tokenPath    string
	httpClient   *http.Client

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

func newBeyondTrustClient(baseURL, clientID, clientSecret, tokenPath string) *beyondTrustClient {
	return &beyondTrustClient{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenPath:    tokenPath,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				Dial: (&net.Dialer{
					Timeout: 10 * time.Second,
				}).Dial,
			},
		},
	}
}

func (c *beyondTrustClient) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}
	return c.refreshToken(ctx)
}

func (c *beyondTrustClient) refreshToken(ctx context.Context) error {
	tokenURL := c.baseURL + "/" + strings.TrimPrefix(c.tokenPath, "/")
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("beyondtrust: token request create: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("beyondtrust: token request: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{StatusCode: resp.StatusCode, URL: tokenURL, Body: string(respBody)}
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return fmt.Errorf("beyondtrust: token response parse: %v", err)
	}
	if tokenResp.AccessToken == "" {
		return errors.New("beyondtrust: missing access_token in token response")
	}

	expiry := tokenResp.ExpiresIn
	if expiry <= 0 {
		expiry = 3600
	}
	c.accessToken = tokenResp.AccessToken
	// Refresh 60 seconds before expiry to avoid using a stale token.
	c.tokenExpiry = time.Now().Add(time.Duration(expiry-60) * time.Second)
	return nil
}

// get issues an authenticated GET and returns the raw response body. A 401
// clears the cached token so the next call triggers a fresh authentication.
func (c *beyondTrustClient) get(ctx context.Context, path string, params url.Values) ([]byte, error) {
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response %q: %v", fullURL, err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		c.mu.Lock()
		c.accessToken = ""
		c.mu.Unlock()
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{StatusCode: resp.StatusCode, URL: fullURL, Body: string(respBody)}
	}

	return respBody, nil
}

func (c *beyondTrustClient) close() {
	c.httpClient.CloseIdleConnections()
}

const (
	defaultPageSize         = 200
	defaultPollInterval     = 1 * time.Minute
	defaultDedupeTTL        = 7 * 24 * time.Hour
	dedupeBucketWindow      = 1 * time.Hour
	defaultMaxPages         = 100
	defaultMaxRetryAttempts = 3
	defaultRetryBaseDelay   = 5 * time.Second
	defaultMaxRetryDelay    = 30 * time.Second
	defaultWindow           = 5 * time.Minute
	defaultTokenPath        = "oauth/connect/token"
	defaultOffsetField      = "offset"
	defaultPageSizeField    = "limit"
	defaultStartTimeField   = "startTime"
	defaultEndTimeField     = "endTime"
	defaultTimestampField   = "timestamp"

	shipTimeout = 10 * time.Second

	// timeLayout is the format used when injecting rolling-window timestamps
	// into BeyondTrust query parameters. RFC 3339 with UTC zone.
	timeLayout = time.RFC3339
)

// itemsArrayKeys are the keys probed, in order, to locate the records array
// when a BeyondTrust endpoint wraps its results in an object envelope. A feed
// may override this via its ItemsPath setting.
var itemsArrayKeys = []string{"events", "data", "items", "pageItems", "value", "results", "records"}

// commonIDFields are probed in order for a stable per-record identifier used
// for deduplication when a feed does not specify an IDField explicitly.
var commonIDFields = []string{"eventId", "auditId", "id", "Id", "guid", "uniqueId"}

// timestampLayouts are the time formats tried when parsing a record timestamp.
var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
}

// BeyondTrustFeed describes a single BeyondTrust API endpoint to poll. New
// event types are added by appending feeds — no code change required.
type BeyondTrustFeed struct {
	// Name labels the feed and becomes the EventType of every shipped event.
	Name string `json:"name" yaml:"name"`

	// Path is the API path relative to BaseURL, e.g. "management.svc/v1/clientEvents".
	Path string `json:"path" yaml:"path"`

	// TimestampField is the JSON field (or "/"-separated nested path) containing
	// the event time. Default: "timestamp".
	TimestampField string `json:"timestamp_field" yaml:"timestamp_field"`

	// IDField is the JSON field used for deduplication. Default: probe
	// commonIDFields, fall back to a content hash.
	IDField string `json:"id_field" yaml:"id_field"`

	// Window, when > 0, enables rolling time-range filtering. On each poll the
	// adapter sets StartTimeField to now-Window-PollInterval and EndTimeField
	// to now. The overlap with the prior poll is absorbed by the deduper.
	Window time.Duration `json:"window" yaml:"window"`

	// StartTimeField / EndTimeField are the query parameter names for the
	// rolling window. Defaults: "startTime" / "endTime".
	StartTimeField string `json:"start_time_field" yaml:"start_time_field"`
	EndTimeField   string `json:"end_time_field" yaml:"end_time_field"`

	// OffsetField is the query parameter name for pagination offset. Default: "offset".
	OffsetField string `json:"offset_field" yaml:"offset_field"`

	// PageSizeField is the query parameter name for page size. Default: "limit".
	PageSizeField string `json:"page_size_field" yaml:"page_size_field"`

	// ItemsPath is the key in the response JSON object that holds the records
	// array. Empty means: auto-detect from a list of common keys.
	ItemsPath string `json:"items_path" yaml:"items_path"`

	// ExtraParams are additional query parameters merged into every request for
	// this feed, e.g. {"computerGroupId": "abc123"} to scope to a group.
	ExtraParams map[string]string `json:"extra_params" yaml:"extra_params"`

	// MaxPages caps how many pages are fetched per poll. Default: 100.
	MaxPages int `json:"max_pages" yaml:"max_pages"`

	// PageBase, when > 0, switches to page-number pagination. The offset
	// counter is converted to a page number as: offset/pageSize + PageBase.
	// Use PageBase=1 for 1-based APIs (e.g. BeyondTrust Management API).
	// When 0 (default), the raw byte offset is sent in OffsetField.
	PageBase int `json:"page_base" yaml:"page_base"`
}

// BeyondTrustConfig is the adapter configuration.
type BeyondTrustConfig struct {
	ClientOptions uspclient.ClientOptions `json:"client_options" yaml:"client_options"`

	// BaseURL is the BeyondTrust EPM server URL, e.g. "https://epm.company.com".
	BaseURL string `json:"base_url" yaml:"base_url"`

	// ClientID and ClientSecret are the OAuth2 API credentials created under
	// Configuration > Settings > API Settings in the EPM web console.
	ClientID     string `json:"client_id" yaml:"client_id"`
	ClientSecret string `json:"client_secret" yaml:"client_secret"`

	// TokenPath is the OAuth2 token endpoint path relative to BaseURL.
	// Default: "oauth/connect/token".
	TokenPath string `json:"token_path" yaml:"token_path"`

	// Feeds is the set of BeyondTrust endpoints to poll. When empty, the
	// adapter defaults to EPM Client Events and Activity Audit Events.
	Feeds []BeyondTrustFeed `json:"feeds" yaml:"feeds"`

	// PageSize is the number of records requested per page. Default: 1000.
	PageSize int `json:"page_size" yaml:"page_size"`

	// PollInterval is the wait between polls of a feed. Default: 1 minute.
	PollInterval time.Duration `json:"poll_interval" yaml:"poll_interval"`

	// DedupeTTL is how long a record's identifier is remembered to suppress
	// re-shipping it on subsequent polls. Default: 7 days.
	DedupeTTL time.Duration `json:"dedupe_ttl" yaml:"dedupe_ttl"`

	// Retry tuning for transient API failures.
	RetryBaseDelay   time.Duration `json:"retry_base_delay" yaml:"retry_base_delay"`
	MaxRetryDelay    time.Duration `json:"max_retry_delay" yaml:"max_retry_delay"`
	MaxRetryAttempts int           `json:"max_retry_attempts" yaml:"max_retry_attempts"`

	// Deduper, when set, replaces the built-in in-memory deduper. Not
	// settable through a config file; exists as a seam for tests.
	Deduper utils.Deduper `json:"-" yaml:"-"`
}

// defaultFeeds returns the out-of-the-box feed set for BeyondTrust EPM Cloud
// (management-api v1):
//
//   - epm_authorization_audits: endpoint activity — authorization requests,
//     privilege elevations, application allow/deny decisions.
//   - epm_activity_audit: administrator actions taken in the EPM web console —
//     policy changes, role assignments, configuration edits.
//
// Both feeds use a 5-minute rolling window so that a poll always covers
// [now-window-pollInterval, now]; the deduper suppresses re-shipping of
// records that fall into successive overlapping windows.
//
// The Management API uses 1-based page-number pagination (PageBase=1) and
// an array date-range filter (StartTimeField == EndTimeField, with a
// SelectionMode=Range extra param).
func defaultFeeds() []BeyondTrustFeed {
	return []BeyondTrustFeed{
		{
			Name:           "epm_authorization_audits",
			Path:           "management-api/v1/AuthorizationRequestAudits",
			TimestampField: "timeOfRequest",
			Window:         defaultWindow,
			StartTimeField: "Filter.TimeOfRequest.Dates",
			EndTimeField:   "Filter.TimeOfRequest.Dates",
			ExtraParams:    map[string]string{"Filter.TimeOfRequest.SelectionMode": "Range"},
			OffsetField:    "Pagination.PageNumber",
			PageSizeField:  "Pagination.PageSize",
			PageBase:       1,
		},
		{
			Name:           "epm_activity_audit",
			Path:           "management-api/v1/ActivityAudits",
			TimestampField: "created",
			Window:         defaultWindow,
			StartTimeField: "Filter.Created.Dates",
			EndTimeField:   "Filter.Created.Dates",
			ExtraParams:    map[string]string{"Filter.Created.SelectionMode": "Range"},
			OffsetField:    "Pagination.PageNumber",
			PageSizeField:  "Pagination.PageSize",
			PageBase:       1,
		},
	}
}

func (c *BeyondTrustConfig) Validate() error {
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
	if c.PageSize <= 0 {
		c.PageSize = defaultPageSize
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
	seenNames := make(map[string]struct{}, len(c.Feeds))
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
		if _, ok := seenNames[f.Name]; ok {
			return fmt.Errorf("feed %q: duplicate name", f.Name)
		}
		seenNames[f.Name] = struct{}{}
		if f.TimestampField == "" {
			f.TimestampField = defaultTimestampField
		}
		if f.MaxPages <= 0 {
			f.MaxPages = defaultMaxPages
		}
		if f.Window > 0 {
			if f.StartTimeField == "" {
				f.StartTimeField = defaultStartTimeField
			}
			if f.EndTimeField == "" {
				f.EndTimeField = defaultEndTimeField
			}
		}
		if f.OffsetField == "" {
			f.OffsetField = defaultOffsetField
		}
		if f.PageSizeField == "" {
			f.PageSizeField = defaultPageSizeField
		}
	}
	return nil
}

// uspSink is the subset of *uspclient.Client the adapter depends on. Using an
// interface lets tests substitute an in-memory sink; *uspclient.Client satisfies
// it unchanged.
type uspSink interface {
	Ship(message *protocol.DataMessage, timeout time.Duration) error
	Drain(timeout time.Duration) error
	Close() ([]*protocol.DataMessage, error)
}

// BeyondTrustAdapter polls one or more BeyondTrust feeds and ships their
// records to LimaCharlie.
type BeyondTrustAdapter struct {
	conf        BeyondTrustConfig
	uspClient   uspSink
	client      *beyondTrustClient
	deduper     utils.Deduper
	ownsDeduper bool

	chStopped chan struct{}
	wgSenders sync.WaitGroup
	doStop    *utils.Event

	closeOnce sync.Once
	closeErr  error

	ctx context.Context
}

// NewBeyondTrustAdapter creates a BeyondTrust adapter wired to LimaCharlie.
func NewBeyondTrustAdapter(ctx context.Context, conf BeyondTrustConfig) (*BeyondTrustAdapter, chan struct{}, error) {
	return newBeyondTrustAdapter(ctx, conf, nil)
}

// newBeyondTrustAdapter is the internal constructor. When sink is non-nil it is
// used in place of a real LimaCharlie client — the seam tests use to capture
// shipped events without a live LC connection.
func newBeyondTrustAdapter(ctx context.Context, conf BeyondTrustConfig, sink uspSink) (*BeyondTrustAdapter, chan struct{}, error) {
	if err := conf.Validate(); err != nil {
		return nil, nil, err
	}

	a := &BeyondTrustAdapter{
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
		deduper, err := utils.NewLocalDeduper(window, conf.DedupeTTL)
		if err != nil {
			return nil, nil, fmt.Errorf("beyondtrust: deduper: %v", err)
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

	a.client = newBeyondTrustClient(conf.BaseURL, conf.ClientID, conf.ClientSecret, conf.TokenPath)
	a.chStopped = make(chan struct{})

	for _, feed := range conf.Feeds {
		a.conf.ClientOptions.DebugLog(fmt.Sprintf("beyondtrust: starting feed %q -> %s", feed.Name, feed.Path))
		a.wgSenders.Add(1)
		go a.runFeed(feed)
	}

	go func() {
		a.wgSenders.Wait()
		close(a.chStopped)
	}()

	return a, a.chStopped, nil
}

// Close stops the adapter. It is idempotent; repeated calls return the result
// of the first call.
func (a *BeyondTrustAdapter) Close() error {
	a.closeOnce.Do(func() {
		a.conf.ClientOptions.DebugLog("beyondtrust: closing")
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

// runFeed polls a single feed forever until the adapter is asked to stop.
func (a *BeyondTrustAdapter) runFeed(feed BeyondTrustFeed) {
	defer a.wgSenders.Done()
	defer a.conf.ClientOptions.DebugLog(fmt.Sprintf("beyondtrust: feed %q stopped", feed.Name))

	isFirstRun := true
	for isFirstRun || !a.doStop.WaitFor(a.conf.PollInterval) {
		isFirstRun = false
		a.pollFeed(feed)
	}
}

// pollFeed fetches one feed once, walking pages until the result set is
// exhausted (a short or empty page) or the feed's MaxPages cap is reached.
func (a *BeyondTrustAdapter) pollFeed(feed BeyondTrustFeed) {
	nSeen := 0
	nShipped := 0

	for offset := 0; !a.doStop.IsSet(); offset += a.conf.PageSize {
		pageNum := offset/a.conf.PageSize + 1
		if pageNum > feed.MaxPages {
			a.conf.ClientOptions.OnWarning(fmt.Sprintf(
				"beyondtrust: feed %q hit max_pages=%d; records past that are not "+
					"collected this poll — raise max_pages or narrow the feed's parameters",
				feed.Name, feed.MaxPages))
			break
		}

		items, ok := a.fetchPage(feed, offset)
		if !ok {
			return
		}
		if len(items) == 0 {
			break
		}

		for _, item := range items {
			nSeen++
			if a.deduper.CheckAndAdd(a.dedupeKey(feed, item)) {
				continue
			}
			if !a.ship(feed, item) {
				return
			}
			nShipped++
		}

		if len(items) < a.conf.PageSize {
			break
		}
	}

	a.conf.ClientOptions.DebugLog(fmt.Sprintf(
		"beyondtrust: feed %q poll complete (seen=%d shipped=%d)", feed.Name, nSeen, nShipped))
}

// fetchPage requests one page of a feed, retrying transient failures with
// exponential backoff. The bool result is false when the poll should be
// abandoned (a permanent error or the adapter is stopping).
func (a *BeyondTrustAdapter) fetchPage(feed BeyondTrustFeed, offset int) ([]utils.Dict, bool) {
	params := a.buildQueryParams(feed, offset)

	var raw []byte
	var err error
	for attempt := 0; attempt < a.conf.MaxRetryAttempts; attempt++ {
		if a.doStop.IsSet() {
			return nil, false
		}

		raw, err = a.client.get(a.ctx, feed.Path, params)
		if err == nil {
			break
		}

		if !isTransientError(err) {
			a.conf.ClientOptions.OnError(fmt.Errorf("beyondtrust: feed %q request failed: %v", feed.Name, err))
			var httpErr *HTTPError
			if errors.As(err, &httpErr) &&
				(httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden) {
				a.conf.ClientOptions.OnError(fmt.Errorf(
					"beyondtrust: HTTP %d — verify client_id, client_secret, and base_url are correct",
					httpErr.StatusCode))
				a.doStop.Set()
			}
			return nil, false
		}

		if attempt+1 >= a.conf.MaxRetryAttempts {
			break
		}
		delay := a.conf.RetryBaseDelay * time.Duration(1<<attempt)
		if delay > a.conf.MaxRetryDelay {
			delay = a.conf.MaxRetryDelay
		}
		a.conf.ClientOptions.OnWarning(fmt.Sprintf(
			"beyondtrust: feed %q transient error (attempt %d/%d), retrying in %v: %v",
			feed.Name, attempt+1, a.conf.MaxRetryAttempts, delay, err))
		if a.doStop.WaitFor(delay) {
			return nil, false
		}
	}
	if err != nil {
		a.conf.ClientOptions.OnError(fmt.Errorf(
			"beyondtrust: feed %q failed after %d attempts: %v", feed.Name, a.conf.MaxRetryAttempts, err))
		return nil, false
	}

	items, err := extractItems(raw, feed.ItemsPath)
	if err != nil {
		a.conf.ClientOptions.OnError(fmt.Errorf("beyondtrust: feed %q response parse error: %v", feed.Name, err))
		return nil, false
	}
	return items, true
}

// buildQueryParams assembles the query parameters for a single page request.
func (a *BeyondTrustAdapter) buildQueryParams(feed BeyondTrustFeed, offset int) url.Values {
	params := url.Values{}
	for k, v := range feed.ExtraParams {
		params.Set(k, v)
	}
	params.Set(feed.PageSizeField, strconv.Itoa(a.conf.PageSize))
	if feed.PageBase > 0 {
		pageNum := offset/a.conf.PageSize + feed.PageBase
		params.Set(feed.OffsetField, strconv.Itoa(pageNum))
	} else {
		params.Set(feed.OffsetField, strconv.Itoa(offset))
	}
	if feed.Window > 0 {
		end := time.Now().UTC()
		start := end.Add(-feed.Window - a.conf.PollInterval)
		// Use Add (not Set) so that when StartTimeField == EndTimeField the
		// values are sent as an array — required by APIs like BeyondTrust that
		// use a single repeated parameter for date ranges.
		params.Add(feed.StartTimeField, start.Format(timeLayout))
		params.Add(feed.EndTimeField, end.Format(timeLayout))
	}
	return params
}

// ship forwards a single record to LimaCharlie. Returns false if the adapter
// should stop due to an unrecoverable shipping error.
func (a *BeyondTrustAdapter) ship(feed BeyondTrustFeed, item utils.Dict) bool {
	msg := &protocol.DataMessage{
		JsonPayload: item,
		EventType:   feed.Name,
		TimestampMs: a.eventTime(feed, item),
	}
	if err := a.uspClient.Ship(msg, shipTimeout); err != nil {
		if err == uspclient.ErrorBufferFull {
			a.conf.ClientOptions.OnWarning("beyondtrust: stream falling behind")
			err = a.uspClient.Ship(msg, 1*time.Hour)
		}
		if err != nil {
			a.conf.ClientOptions.OnError(fmt.Errorf("beyondtrust: Ship(): %v", err))
			a.doStop.Set()
			return false
		}
	}
	return true
}

// eventTime extracts the record's event time, falling back to now when the
// configured timestamp field is absent or unparseable.
func (a *BeyondTrustAdapter) eventTime(feed BeyondTrustFeed, item utils.Dict) uint64 {
	field := feed.TimestampField
	if field == "" {
		field = defaultTimestampField
	}
	if raw := item.FindOneString(field); raw != "" {
		if t, ok := parseTimestamp(raw); ok {
			return uint64(t.UnixMilli())
		}
		a.conf.ClientOptions.DebugLog(fmt.Sprintf(
			"beyondtrust: feed %q unparseable timestamp %q at field %q", feed.Name, raw, field))
	}
	return uint64(time.Now().UnixMilli())
}

// dedupeKey returns a stable deduplication key for a record, namespaced by
// feed so identifiers cannot collide across feeds.
func (a *BeyondTrustAdapter) dedupeKey(feed BeyondTrustFeed, item utils.Dict) string {
	return feed.Name + "|" + recordID(feed, item)
}

// recordID resolves a record's identifier: the feed's IDField if set,
// otherwise a probe of common id fields, otherwise a content hash.
func recordID(feed BeyondTrustFeed, item utils.Dict) string {
	if feed.IDField != "" {
		if id := fieldAsString(item, feed.IDField); id != "" {
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

// fieldAsString reads a field as a string, accepting numeric values too (ids
// are sometimes integers in the BeyondTrust API).
func fieldAsString(item utils.Dict, path string) string {
	if s := item.FindOneString(path); s != "" {
		return s
	}
	if ints := item.FindInt(path); len(ints) > 0 {
		return strconv.FormatUint(ints[0], 10)
	}
	return ""
}

// extractItems parses a BeyondTrust API response into a slice of records. It
// accepts both a bare JSON array and an object envelope; for an envelope it
// uses itemsPath when provided, otherwise it auto-detects a common key.
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
				return nil, fmt.Errorf("items_path %q not present in response object (keys: %v)", itemsPath, keysOf(obj))
			}
		} else {
			for _, k := range itemsArrayKeys {
				if v, ok := obj[k]; ok {
					arrRaw = v
					break
				}
			}
			if arrRaw == nil {
				return nil, fmt.Errorf("could not locate a records array in response object (keys: %v); set items_path", keysOf(obj))
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

// rawMessagesToDicts decodes each record with utils.UnmarshalCleanJSON, which
// preserves integer precision (no float coercion). Records that are not
// non-empty JSON objects are skipped rather than failing the whole page.
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
