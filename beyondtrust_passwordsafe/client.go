// Package usp_beyondtrust_passwordsafe implements a USP adapter for the
// BeyondTrust Password Safe REST API (/BeyondTrust/api/public/v3/).
//
// Two authentication modes are supported:
//
//   - OAuth2 (recommended for cloud): set client_id and client_secret. The
//     adapter obtains a bearer token from /Auth/Connect/Token and refreshes it
//     automatically before expiry.
//
//   - PS-Auth (on-premises): set api_key (and optionally run_as_user). The
//     adapter signs in via /Auth/SignAppIn, receives a session cookie, and
//     re-authenticates automatically on HTTP 401.
//
// Two feeds are enabled by default: the Activity Log (all user and system
// actions) and Sessions (privileged-access checkout events). Additional
// Password Safe endpoints can be added as feeds without changing code.
package usp_beyondtrust_passwordsafe

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
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
	defaultSignInPath   = "BeyondTrust/api/public/v3/Auth/SignAppIn"
	defaultSignOutPath  = "BeyondTrust/api/public/v3/Auth/Signout"
	defaultTokenPath    = "BeyondTrust/api/public/v3/Auth/Connect/Token"
	defaultPageSize     = 100
	defaultPollInterval = 1 * time.Minute
	defaultDedupeTTL    = 7 * 24 * time.Hour
	dedupeBucketWindow  = 1 * time.Hour
	defaultMaxPages     = 100

	defaultMaxRetryAttempts = 3
	defaultRetryBaseDelay   = 5 * time.Second
	defaultMaxRetryDelay    = 30 * time.Second
	defaultOffsetField      = "offset"
	defaultPageSizeField    = "limit"
	defaultStartTimeField   = "startTime"
	defaultEndTimeField     = "endTime"
	defaultTimestampField   = "createdDate"

	shipTimeout = 10 * time.Second
	timeLayout  = time.RFC3339
)

var itemsArrayKeys = []string{"data", "items", "events", "value", "results", "records"}
var commonIDFields = []string{"activityLogID", "sessionID", "id", "Id", "guid"}
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

// ── PS-Auth HTTP client ───────────────────────────────────────────────────────

// passwordSafeClient handles both PS-Auth (session-cookie) and OAuth2
// (bearer-token) authentication against the Password Safe REST API.
//
// OAuth2 mode is active when clientID is non-empty; otherwise PS-Auth is used.
type passwordSafeClient struct {
	baseURL     string
	signInPath  string
	signOutPath string
	httpClient  *http.Client

	// PS-Auth fields
	apiKey    string
	runAsUser string

	// OAuth2 fields
	clientID     string
	clientSecret string
	tokenPath    string

	mu          sync.Mutex
	signedIn    bool      // PS-Auth session state
	accessToken string    // OAuth2 cached token
	tokenExpiry time.Time // OAuth2 token expiry
}

func newPasswordSafeClient(baseURL, apiKey, runAsUser, signInPath, signOutPath, clientID, clientSecret, tokenPath string) (*passwordSafeClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("beyondtrust_passwordsafe: cookie jar: %v", err)
	}
	transport := &http.Transport{
		Dial: (&net.Dialer{Timeout: 10 * time.Second}).Dial,
		// BeyondTrust Password Safe requests TLS renegotiation;
		// Go disallows it by default.
		TLSClientConfig: &tls.Config{
			Renegotiation: tls.RenegotiateFreelyAsClient,
		},
	}
	return &passwordSafeClient{
		baseURL:      strings.TrimRight(baseURL, "/"),
		apiKey:       apiKey,
		runAsUser:    runAsUser,
		signInPath:   signInPath,
		signOutPath:  signOutPath,
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenPath:    tokenPath,
		httpClient: &http.Client{
			Jar:       jar,
			Timeout:   60 * time.Second,
			Transport: transport,
		},
	}, nil
}

// psAuthHeader builds the PS-Auth Authorization header value.
func (c *passwordSafeClient) psAuthHeader() string {
	if c.runAsUser != "" {
		return fmt.Sprintf(`PS-Auth key="%s"; runas="%s"`, c.apiKey, c.runAsUser)
	}
	return fmt.Sprintf(`PS-Auth key="%s"`, c.apiKey)
}

func (c *passwordSafeClient) ensureSignedIn(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.signedIn {
		return nil
	}
	return c.doSignIn(ctx)
}

func (c *passwordSafeClient) doSignIn(ctx context.Context) error {
	signInURL := c.baseURL + "/" + strings.TrimPrefix(c.signInPath, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, signInURL, nil)
	if err != nil {
		return fmt.Errorf("beyondtrust_passwordsafe: sign-in request create: %v", err)
	}
	req.Header.Set("Authorization", c.psAuthHeader())
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("beyondtrust_passwordsafe: sign-in request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return &httpError{StatusCode: resp.StatusCode, URL: signInURL}
	}
	c.signedIn = true
	return nil
}

// signOut sends a best-effort sign-out request; errors are ignored.
func (c *passwordSafeClient) signOut(ctx context.Context) {
	signOutURL := c.baseURL + "/" + strings.TrimPrefix(c.signOutPath, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, signOutURL, nil)
	if err != nil {
		return
	}
	resp, err := c.httpClient.Do(req)
	if err == nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
}

// get issues an authenticated GET using OAuth2 or PS-Auth depending on config.
func (c *passwordSafeClient) get(ctx context.Context, path string, params url.Values) ([]byte, error) {
	if c.clientID != "" {
		return c.getOAuth2(ctx, path, params)
	}
	return c.getPSAuth(ctx, path, params)
}

// ensureToken obtains or refreshes the OAuth2 bearer token.
func (c *passwordSafeClient) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}
	tokenURL := c.baseURL + "/" + strings.TrimPrefix(c.tokenPath, "/")
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("beyondtrust_passwordsafe: token request create: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("beyondtrust_passwordsafe: token request: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return &httpError{StatusCode: resp.StatusCode, URL: tokenURL, Body: string(respBody)}
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tok); err != nil {
		return fmt.Errorf("beyondtrust_passwordsafe: token parse: %v", err)
	}
	if tok.AccessToken == "" {
		return errors.New("beyondtrust_passwordsafe: missing access_token in token response")
	}
	expiry := tok.ExpiresIn
	if expiry <= 0 {
		expiry = 3600
	}
	c.accessToken = tok.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(expiry-60) * time.Second)
	return nil
}

func (c *passwordSafeClient) getOAuth2(ctx context.Context, path string, params url.Values) ([]byte, error) {
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
	body, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read response %q: %v", fullURL, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		c.mu.Lock()
		c.accessToken = ""
		c.mu.Unlock()
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{StatusCode: resp.StatusCode, URL: fullURL, Body: string(body)}
	}
	return body, nil
}

// getPSAuth issues an authenticated GET using the PS-Auth session-cookie scheme.
// On 401 the session flag is cleared so the next call triggers a fresh sign-in.
func (c *passwordSafeClient) getPSAuth(ctx context.Context, path string, params url.Values) ([]byte, error) {
	if err := c.ensureSignedIn(ctx); err != nil {
		return nil, err
	}

	fullURL := c.baseURL + "/" + strings.TrimPrefix(path, "/")
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request %q: %v", fullURL, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request %q: %v", fullURL, err)
	}
	defer resp.Body.Close()

	body, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read response %q: %v", fullURL, err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		c.mu.Lock()
		c.signedIn = false
		c.mu.Unlock()
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{StatusCode: resp.StatusCode, URL: fullURL, Body: string(body)}
	}
	return body, nil
}

func (c *passwordSafeClient) close(ctx context.Context) {
	c.signOut(ctx)
	c.httpClient.CloseIdleConnections()
}

// readBody reads the response body, decompressing gzip if the magic bytes are present.
func readBody(resp *http.Response) ([]byte, error) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Decompress if gzip magic bytes present (handles Content-Type: application/gzip).
	if len(raw) > 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		gr, err := gzip.NewReader(strings.NewReader(string(raw)))
		if err != nil {
			return raw, nil // not actually gzip; return as-is
		}
		defer gr.Close()
		if decompressed, err := io.ReadAll(gr); err == nil {
			return decompressed, nil
		}
	}
	return raw, nil
}

// ── Feed and config types ─────────────────────────────────────────────────────

// PasswordSafeFeed describes a single Password Safe REST endpoint to poll.
type PasswordSafeFeed struct {
	Name           string            `json:"name" yaml:"name"`
	Path           string            `json:"path" yaml:"path"`
	TimestampField string            `json:"timestamp_field" yaml:"timestamp_field"`
	IDField        string            `json:"id_field" yaml:"id_field"`
	Window         time.Duration     `json:"window" yaml:"window"`
	StartTimeField string            `json:"start_time_field" yaml:"start_time_field"`
	EndTimeField   string            `json:"end_time_field" yaml:"end_time_field"`
	OffsetField    string            `json:"offset_field" yaml:"offset_field"`
	PageSizeField  string            `json:"page_size_field" yaml:"page_size_field"`
	ItemsPath      string            `json:"items_path" yaml:"items_path"`
	ExtraParams    map[string]string `json:"extra_params" yaml:"extra_params"`
	MaxPages       int               `json:"max_pages" yaml:"max_pages"`
}

// PasswordSafeConfig is the adapter configuration.
type PasswordSafeConfig struct {
	ClientOptions uspclient.ClientOptions `json:"client_options" yaml:"client_options"`

	// BaseURL is the Password Safe server URL, e.g. "https://passwordsafe.company.com".
	BaseURL string `json:"base_url" yaml:"base_url"`

	// OAuth2 credentials (recommended for cloud instances). When set, the
	// adapter uses bearer-token auth instead of PS-Auth.
	ClientID     string `json:"client_id" yaml:"client_id"`
	ClientSecret string `json:"client_secret" yaml:"client_secret"`

	// TokenPath is the OAuth2 token endpoint path relative to BaseURL.
	// Default: "BeyondTrust/api/public/v3/Auth/Connect/Token".
	TokenPath string `json:"token_path" yaml:"token_path"`

	// APIKey is the PS-Auth API key (on-premises / legacy). Leave empty when
	// using OAuth2 (client_id / client_secret).
	APIKey string `json:"api_key" yaml:"api_key"`

	// RunAsUser is the optional PS-Auth runas username. Required by some
	// on-premises Password Safe configurations.
	RunAsUser string `json:"run_as_user" yaml:"run_as_user"`

	// SignInPath and SignOutPath are the PS-Auth endpoint paths relative to BaseURL.
	// Defaults: "BeyondTrust/api/public/v3/Auth/SignAppIn" / ".../Signout".
	SignInPath  string `json:"sign_in_path" yaml:"sign_in_path"`
	SignOutPath string `json:"sign_out_path" yaml:"sign_out_path"`

	Feeds            []PasswordSafeFeed `json:"feeds" yaml:"feeds"`
	PageSize         int                `json:"page_size" yaml:"page_size"`
	PollInterval     time.Duration      `json:"poll_interval" yaml:"poll_interval"`
	DedupeTTL        time.Duration      `json:"dedupe_ttl" yaml:"dedupe_ttl"`
	RetryBaseDelay   time.Duration      `json:"retry_base_delay" yaml:"retry_base_delay"`
	MaxRetryDelay    time.Duration      `json:"max_retry_delay" yaml:"max_retry_delay"`
	MaxRetryAttempts int                `json:"max_retry_attempts" yaml:"max_retry_attempts"`

	Deduper utils.Deduper `json:"-" yaml:"-"`
}

// defaultFeeds returns the default Password Safe security feeds:
//
//   - sessions:  privileged-access checkout sessions (account check-out/in events).
//   - requests:  credential requests and approvals — who requested access to what
//     privileged account, whether it was approved or denied, and by whom.
func defaultFeeds() []PasswordSafeFeed {
	return []PasswordSafeFeed{
		{
			Name:           "sessions",
			Path:           "BeyondTrust/api/public/v3/Sessions",
			TimestampField: "startTime",
			IDField:        "sessionID",
		},
		{
			Name:           "requests",
			Path:           "BeyondTrust/api/public/v3/Requests",
			TimestampField: "requestedDate",
			IDField:        "requestID",
		},
	}
}

func (c *PasswordSafeConfig) Validate() error {
	if err := c.ClientOptions.Validate(); err != nil {
		return fmt.Errorf("client_options: %v", err)
	}
	if c.BaseURL == "" {
		return errors.New("missing base_url")
	}
	// Strip the API path if the user included it in base_url (e.g.
	// ".../BeyondTrust/api/public/v3") — the feed paths already contain it,
	// so including it in base_url doubles every request URL.
	if u, err := url.Parse(c.BaseURL); err == nil {
		if idx := strings.Index(u.Path, "/BeyondTrust/api/public"); idx >= 0 {
			u.Path = u.Path[:idx]
		}
		c.BaseURL = strings.TrimRight(u.String(), "/")
	}
	if c.ClientID != "" {
		if c.ClientSecret == "" {
			return errors.New("client_secret required when client_id is set")
		}
		if c.TokenPath == "" {
			c.TokenPath = defaultTokenPath
		}
	} else {
		if c.APIKey == "" {
			return errors.New("missing api_key (or set client_id/client_secret for OAuth2)")
		}
		if c.SignInPath == "" {
			c.SignInPath = defaultSignInPath
		}
		if c.SignOutPath == "" {
			c.SignOutPath = defaultSignOutPath
		}
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

// ── Adapter ───────────────────────────────────────────────────────────────────

type uspSink interface {
	Ship(message *protocol.DataMessage, timeout time.Duration) error
	Drain(timeout time.Duration) error
	Close() ([]*protocol.DataMessage, error)
}

// PasswordSafeAdapter polls one or more Password Safe feeds and ships events
// to LimaCharlie.
type PasswordSafeAdapter struct {
	conf        PasswordSafeConfig
	uspClient   uspSink
	client      *passwordSafeClient
	deduper     utils.Deduper
	ownsDeduper bool

	chStopped chan struct{}
	wgSenders sync.WaitGroup
	doStop    *utils.Event

	closeOnce sync.Once
	closeErr  error

	ctx context.Context
}

// NewPasswordSafeAdapter creates a Password Safe adapter wired to LimaCharlie.
func NewPasswordSafeAdapter(ctx context.Context, conf PasswordSafeConfig) (*PasswordSafeAdapter, chan struct{}, error) {
	return newPasswordSafeAdapter(ctx, conf, nil)
}

func newPasswordSafeAdapter(ctx context.Context, conf PasswordSafeConfig, sink uspSink) (*PasswordSafeAdapter, chan struct{}, error) {
	if err := conf.Validate(); err != nil {
		return nil, nil, err
	}

	a := &PasswordSafeAdapter{
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
			return nil, nil, fmt.Errorf("beyondtrust_passwordsafe: deduper: %v", err)
		}
		a.deduper = d
		a.ownsDeduper = true
	}

	client, err := newPasswordSafeClient(conf.BaseURL, conf.APIKey, conf.RunAsUser, conf.SignInPath, conf.SignOutPath, conf.ClientID, conf.ClientSecret, conf.TokenPath)
	if err != nil {
		if a.ownsDeduper {
			a.deduper.Close()
		}
		return nil, nil, err
	}
	a.client = client

	if sink != nil {
		a.uspClient = sink
	} else {
		uspClient, err := uspclient.NewClient(ctx, conf.ClientOptions)
		if err != nil {
			a.client.close(ctx)
			if a.ownsDeduper {
				a.deduper.Close()
			}
			return nil, nil, err
		}
		a.uspClient = uspClient
	}

	a.chStopped = make(chan struct{})

	for _, feed := range conf.Feeds {
		a.conf.ClientOptions.DebugLog(fmt.Sprintf("beyondtrust_passwordsafe: starting feed %q -> %s", feed.Name, feed.Path))
		a.wgSenders.Add(1)
		go a.runFeed(feed)
	}

	go func() {
		a.wgSenders.Wait()
		close(a.chStopped)
	}()

	return a, a.chStopped, nil
}

func (a *PasswordSafeAdapter) Close() error {
	a.closeOnce.Do(func() {
		a.conf.ClientOptions.DebugLog("beyondtrust_passwordsafe: closing")
		a.doStop.Set()
		a.wgSenders.Wait()
		err1 := a.uspClient.Drain(1 * time.Minute)
		_, err2 := a.uspClient.Close()
		a.client.close(a.ctx)
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

func (a *PasswordSafeAdapter) runFeed(feed PasswordSafeFeed) {
	defer a.wgSenders.Done()
	defer a.conf.ClientOptions.DebugLog(fmt.Sprintf("beyondtrust_passwordsafe: feed %q stopped", feed.Name))

	isFirstRun := true
	for isFirstRun || !a.doStop.WaitFor(a.conf.PollInterval) {
		isFirstRun = false
		if permanent := a.pollFeed(feed); permanent {
			return
		}
	}
}

// pollFeed fetches one poll of a feed. Returns true if the feed should stop
// permanently (e.g. 403 permissions error for this specific endpoint).
func (a *PasswordSafeAdapter) pollFeed(feed PasswordSafeFeed) (permanent bool) {
	nSeen, nShipped := 0, 0

	for offset := 0; !a.doStop.IsSet(); offset += a.conf.PageSize {
		pageNum := offset/a.conf.PageSize + 1
		if pageNum > feed.MaxPages {
			a.conf.ClientOptions.OnWarning(fmt.Sprintf(
				"beyondtrust_passwordsafe: feed %q hit max_pages=%d", feed.Name, feed.MaxPages))
			break
		}

		items, ok, perm := a.fetchPage(feed, offset)
		if !ok {
			return perm
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
				return false
			}
			nShipped++
		}

		if len(items) < a.conf.PageSize {
			break
		}
	}

	a.conf.ClientOptions.DebugLog(fmt.Sprintf(
		"beyondtrust_passwordsafe: feed %q poll complete (seen=%d shipped=%d)", feed.Name, nSeen, nShipped))
	return false
}

// fetchPage fetches one page of results. Returns (items, ok, permanent).
// ok=false means skip the rest of this poll; permanent=true means stop this
// feed entirely (e.g. the endpoint does not exist or access is denied).
// A 401 is treated as a global credential failure and stops all feeds via doStop.
func (a *PasswordSafeAdapter) fetchPage(feed PasswordSafeFeed, offset int) ([]utils.Dict, bool, bool) {
	params := a.buildQueryParams(feed, offset)

	var raw []byte
	var err error
	for attempt := 0; attempt < a.conf.MaxRetryAttempts; attempt++ {
		if a.doStop.IsSet() {
			return nil, false, false
		}
		raw, err = a.client.get(a.ctx, feed.Path, params)
		if err == nil {
			break
		}
		if !isTransientError(err) {
			a.conf.ClientOptions.OnError(fmt.Errorf("beyondtrust_passwordsafe: feed %q request failed: %v", feed.Name, err))
			var he *httpError
			if errors.As(err, &he) {
				switch he.StatusCode {
				case http.StatusUnauthorized:
					// Credential failure affects all feeds.
					a.conf.ClientOptions.OnError(fmt.Errorf(
						"beyondtrust_passwordsafe: HTTP 401 — verify credentials; stopping adapter"))
					a.doStop.Set()
					return nil, false, true
				case http.StatusForbidden, http.StatusNotFound:
					// Permission or missing endpoint — stop only this feed.
					a.conf.ClientOptions.OnError(fmt.Errorf(
						"beyondtrust_passwordsafe: HTTP %d on feed %q — stopping this feed (check role assignments or feed path)",
						he.StatusCode, feed.Name))
					return nil, false, true
				}
			}
			return nil, false, false
		}
		if attempt+1 >= a.conf.MaxRetryAttempts {
			break
		}
		delay := a.conf.RetryBaseDelay * time.Duration(1<<attempt)
		if delay > a.conf.MaxRetryDelay {
			delay = a.conf.MaxRetryDelay
		}
		a.conf.ClientOptions.OnWarning(fmt.Sprintf(
			"beyondtrust_passwordsafe: feed %q transient error (attempt %d/%d), retrying in %v: %v",
			feed.Name, attempt+1, a.conf.MaxRetryAttempts, delay, err))
		if a.doStop.WaitFor(delay) {
			return nil, false, false
		}
	}
	if err != nil {
		a.conf.ClientOptions.OnError(fmt.Errorf(
			"beyondtrust_passwordsafe: feed %q failed after %d attempts: %v", feed.Name, a.conf.MaxRetryAttempts, err))
		return nil, false, false
	}

	items, err := extractItems(raw, feed.ItemsPath)
	if err != nil {
		a.conf.ClientOptions.OnError(fmt.Errorf("beyondtrust_passwordsafe: feed %q parse error: %v", feed.Name, err))
		return nil, false, false
	}
	return items, true, false
}

func (a *PasswordSafeAdapter) buildQueryParams(feed PasswordSafeFeed, offset int) url.Values {
	params := url.Values{}
	for k, v := range feed.ExtraParams {
		params.Set(k, v)
	}
	params.Set(feed.PageSizeField, strconv.Itoa(a.conf.PageSize))
	params.Set(feed.OffsetField, strconv.Itoa(offset))
	if feed.Window > 0 {
		end := time.Now().UTC()
		start := end.Add(-feed.Window - a.conf.PollInterval)
		params.Set(feed.StartTimeField, start.Format(timeLayout))
		params.Set(feed.EndTimeField, end.Format(timeLayout))
	}
	return params
}

func (a *PasswordSafeAdapter) ship(feed PasswordSafeFeed, item utils.Dict) bool {
	msg := &protocol.DataMessage{
		JsonPayload: item,
		EventType:   feed.Name,
		TimestampMs: a.eventTime(feed, item),
	}
	if err := a.uspClient.Ship(msg, shipTimeout); err != nil {
		if err == uspclient.ErrorBufferFull {
			a.conf.ClientOptions.OnWarning("beyondtrust_passwordsafe: stream falling behind")
			err = a.uspClient.Ship(msg, 1*time.Hour)
		}
		if err != nil {
			a.conf.ClientOptions.OnError(fmt.Errorf("beyondtrust_passwordsafe: Ship(): %v", err))
			a.doStop.Set()
			return false
		}
	}
	return true
}

func (a *PasswordSafeAdapter) eventTime(feed PasswordSafeFeed, item utils.Dict) uint64 {
	if raw := item.FindOneString(feed.TimestampField); raw != "" {
		if t, ok := parseTimestamp(raw); ok {
			return uint64(t.UnixMilli())
		}
	}
	return uint64(time.Now().UnixMilli())
}

func (a *PasswordSafeAdapter) dedupeKey(feed PasswordSafeFeed, item utils.Dict) string {
	return feed.Name + "|" + recordID(feed.IDField, item)
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
