package usp_gitlab

import (
	"bytes"
	"context"
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
	defaultURL  = "https://gitlab.com"
	apiBasePath = "/api/v4"

	// Scopes of the GitLab hierarchy events can be collected from.
	scopeInstance = "instance"
	scopeGroup    = "group"
	scopeProject  = "project"

	// Collectable event types.
	eventTypeAudit    = "audit_events"
	eventTypeActivity = "events"

	// GitLab caps per_page at 100.
	pageSize = 100

	// Upper bound on the number of pages fetched in a single cycle. Hitting
	// it is not an error: the watermark has advanced, so the next cycle
	// resumes where this one stopped.
	maxPagesPerCycle = 500

	// Events are re-queried this far back on every cycle so that records
	// committed out of order are not missed. The deduper drops the repeats.
	overlapPeriod = 30 * time.Second

	defaultPollIntervalSec = 60

	maxAttempts     = 3
	baseRetryPeriod = 5 * time.Second
)

type GitLabConfig struct {
	ClientOptions uspclient.ClientOptions `json:"client_options" yaml:"client_options"`

	// Personal, group or project access token, sent as PRIVATE-TOKEN.
	Token string `json:"token" yaml:"token"`
	// Base URL of the GitLab instance, defaults to https://gitlab.com.
	URL string `json:"url" yaml:"url"`
	// One of instance, group or project.
	Scope string `json:"scope" yaml:"scope"`
	// Comma separated group or project IDs (or full paths).
	// Required unless the scope is instance.
	EntityIDs string `json:"entity_ids" yaml:"entity_ids"`
	// Comma separated list of audit_events and/or events.
	EventTypes string `json:"event_types" yaml:"event_types"`
	// RFC3339 timestamp to start collecting from, defaults to now.
	StartTime string `json:"start_time" yaml:"start_time"`
	// Seconds between polling cycles, defaults to 60.
	PollIntervalSec uint64 `json:"poll_interval_sec" yaml:"poll_interval_sec"`
}

// stream is a single (entity, event type) pair collected by one goroutine.
type stream struct {
	eventType string
	entityID  string
	path      string
	name      string
}

// streamState is what one collector learns about its endpoint and carries
// between polling cycles.
type streamState struct {
	// Keyset pagination is preferred, but GitLab does not offer it on every
	// audit event endpoint or version. The first rejection downgrades this
	// stream to offset pagination for the life of the process.
	useKeyset bool
	// ceiling caps the next request when a window held more events than one
	// cycle could read, so the remainder is collected before moving on.
	ceiling time.Time
	// pendingSince holds the watermark to adopt once that backlog is drained.
	pendingSince time.Time
}

// errKeysetUnsupported marks GitLab's refusal of keyset pagination, which is a
// signal to downgrade rather than a failure worth reporting.
var errKeysetUnsupported = errors.New("keyset pagination unsupported")

type GitLabAdapter struct {
	conf       GitLabConfig
	uspClient  *uspclient.Client
	httpClient *http.Client
	streams    []stream

	chStopped chan struct{}
	wgSenders sync.WaitGroup
	doStop    *utils.Event

	ctx    context.Context
	dedupe utils.Deduper
}

func (c *GitLabConfig) Validate() error {
	if err := c.ClientOptions.Validate(); err != nil {
		return fmt.Errorf("client_options: %v", err)
	}
	if c.Token == "" {
		return errors.New("missing token")
	}

	if c.URL == "" {
		c.URL = defaultURL
	}
	if !strings.HasPrefix(c.URL, "http://") && !strings.HasPrefix(c.URL, "https://") {
		c.URL = "https://" + c.URL
	}
	c.URL = strings.TrimSuffix(c.URL, "/")
	// Accept a URL that already points at the API root.
	c.URL = strings.TrimSuffix(c.URL, apiBasePath)
	c.URL = strings.TrimSuffix(c.URL, "/")
	if _, err := url.Parse(c.URL); err != nil {
		return fmt.Errorf("invalid url: %v", err)
	}

	if c.Scope == "" {
		c.Scope = scopeInstance
	}
	c.Scope = strings.ToLower(strings.TrimSpace(c.Scope))
	switch c.Scope {
	case scopeInstance, scopeGroup, scopeProject:
	default:
		return fmt.Errorf("invalid scope: %s (expected %s, %s or %s)", c.Scope, scopeInstance, scopeGroup, scopeProject)
	}

	if c.EventTypes == "" {
		c.EventTypes = eventTypeAudit
	}

	if c.StartTime != "" {
		if _, err := time.Parse(time.RFC3339, c.StartTime); err != nil {
			return fmt.Errorf("invalid start_time: %v", err)
		}
	}

	if c.PollIntervalSec == 0 {
		c.PollIntervalSec = defaultPollIntervalSec
	}

	// Building the streams validates the scope, entity and event type combination.
	if _, err := c.buildStreams(); err != nil {
		return err
	}

	return nil
}

// buildStreams resolves the configuration into the concrete set of API
// endpoints to poll.
func (c *GitLabConfig) buildStreams() ([]stream, error) {
	entities := splitList(c.EntityIDs)
	if c.Scope == scopeInstance {
		if len(entities) != 0 {
			return nil, errors.New("entity_ids cannot be used with the instance scope")
		}
		// A single unnamed entity: the instance itself.
		entities = []string{""}
	} else if len(entities) == 0 {
		return nil, fmt.Errorf("missing entity_ids, required with the %s scope", c.Scope)
	}

	eventTypes := splitList(c.EventTypes)
	if len(eventTypes) == 0 {
		return nil, errors.New("missing event_types")
	}

	streams := make([]stream, 0, len(entities)*len(eventTypes))
	for _, et := range eventTypes {
		et = strings.ToLower(et)
		if et != eventTypeAudit && et != eventTypeActivity {
			return nil, fmt.Errorf("invalid event_types value: %s (expected %s or %s)", et, eventTypeAudit, eventTypeActivity)
		}
		// GitLab has no group level Events API, only audit events.
		if et == eventTypeActivity && c.Scope == scopeGroup {
			return nil, fmt.Errorf("gitlab does not expose %s at the %s scope, use %s instead", eventTypeActivity, scopeGroup, eventTypeAudit)
		}
		for _, entity := range entities {
			path, err := endpointPath(c.Scope, entity, et)
			if err != nil {
				return nil, err
			}
			name := et
			if entity != "" {
				name = fmt.Sprintf("%s %s %s", c.Scope, entity, et)
			}
			streams = append(streams, stream{
				eventType: et,
				entityID:  entity,
				path:      path,
				name:      name,
			})
		}
	}

	return streams, nil
}

// endpointPath maps a scope and event type to the API path. Group and project
// IDs may be numeric or a full path, which has to be URL encoded.
func endpointPath(scope string, entityID string, eventType string) (string, error) {
	switch scope {
	case scopeInstance:
		switch eventType {
		case eventTypeAudit:
			return apiBasePath + "/audit_events", nil
		case eventTypeActivity:
			// Events visible to the authenticated user.
			return apiBasePath + "/events", nil
		}
	case scopeGroup:
		if eventType == eventTypeAudit {
			return fmt.Sprintf("%s/groups/%s/audit_events", apiBasePath, url.PathEscape(entityID)), nil
		}
	case scopeProject:
		switch eventType {
		case eventTypeAudit:
			return fmt.Sprintf("%s/projects/%s/audit_events", apiBasePath, url.PathEscape(entityID)), nil
		case eventTypeActivity:
			return fmt.Sprintf("%s/projects/%s/events", apiBasePath, url.PathEscape(entityID)), nil
		}
	}
	return "", fmt.Errorf("unsupported scope and event type combination: %s / %s", scope, eventType)
}

func splitList(v string) []string {
	out := []string{}
	for _, e := range strings.Split(v, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		out = append(out, e)
	}
	return out
}

func NewGitLabAdapter(ctx context.Context, conf GitLabConfig) (*GitLabAdapter, chan struct{}, error) {
	if err := conf.Validate(); err != nil {
		return nil, nil, err
	}

	streams, err := conf.buildStreams()
	if err != nil {
		return nil, nil, err
	}

	a := &GitLabAdapter{
		conf:    conf,
		ctx:     ctx,
		doStop:  utils.NewEvent(),
		streams: streams,
	}

	// The overlap re-reads recent events on every cycle, the deduper keeps
	// them from being shipped twice.
	if a.dedupe, err = utils.NewLocalDeduper(1*time.Minute, 1*time.Hour); err != nil {
		return nil, nil, err
	}

	if a.uspClient, err = uspclient.NewClient(ctx, conf.ClientOptions); err != nil {
		a.dedupe.Close()
		return nil, nil, err
	}

	a.httpClient = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).Dial,
		},
	}

	a.chStopped = make(chan struct{})

	for _, s := range a.streams {
		a.conf.ClientOptions.DebugLog(fmt.Sprintf("starting to fetch %s from %s", s.name, s.path))
		a.wgSenders.Add(1)
		go a.fetchEvents(s)
	}

	go func() {
		a.wgSenders.Wait()
		close(a.chStopped)
	}()

	return a, a.chStopped, nil
}

func (a *GitLabAdapter) Close() error {
	a.conf.ClientOptions.DebugLog("closing")
	a.doStop.Set()
	a.wgSenders.Wait()
	a.dedupe.Close()
	err1 := a.uspClient.Drain(1 * time.Minute)
	_, err2 := a.uspClient.Close()
	a.httpClient.CloseIdleConnections()

	if err1 != nil {
		return err1
	}

	return err2
}

func (a *GitLabAdapter) fetchEvents(s stream) {
	defer a.wgSenders.Done()
	defer a.conf.ClientOptions.DebugLog(fmt.Sprintf("fetching of %s exiting", s.name))

	since := time.Now().UTC().Add(-overlapPeriod)
	if a.conf.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, a.conf.StartTime); err == nil {
			since = t.UTC()
		}
	}

	st := &streamState{useKeyset: s.eventType == eventTypeAudit}
	pollInterval := time.Duration(a.conf.PollIntervalSec) * time.Second

	isFirstRun := true
	for isFirstRun || !a.doStop.WaitFor(pollInterval) {
		isFirstRun = false

		var nFetched int
		if s.eventType == eventTypeAudit {
			since, nFetched = a.fetchAuditEvents(s, since, st)
		} else {
			since, nFetched = a.fetchActivityEvents(s, since)
		}

		a.conf.ClientOptions.DebugLog(fmt.Sprintf("fetched %d events for %s", nFetched, s.name))

		if a.doStop.IsSet() {
			return
		}
	}
}

// fetchAuditEvents collects one window of audit events, retrying once with
// offset pagination if this endpoint turns out not to support keyset. It
// returns the watermark the next cycle should start from.
func (a *GitLabAdapter) fetchAuditEvents(s stream, since time.Time, st *streamState) (time.Time, int) {
	for {
		newSince, nFetched, err := a.fetchAuditWindow(s, since, st)
		if errors.Is(err, errKeysetUnsupported) && st.useKeyset {
			a.conf.ClientOptions.DebugLog(fmt.Sprintf("%s does not support keyset pagination, falling back to offset", s.name))
			st.useKeyset = false
			continue
		}
		return newSince, nFetched
	}
}

// fetchAuditWindow pages through the Audit Events API once. Results are asked
// for oldest first, but not every GitLab version honours the ordering, so the
// direction actually returned decides how far the watermark may advance.
func (a *GitLabAdapter) fetchAuditWindow(s stream, since time.Time, st *streamState) (time.Time, int, error) {
	q := url.Values{}
	q.Set("per_page", strconv.Itoa(pageSize))
	q.Set("sort", "asc")
	if st.useKeyset {
		// Offset pagination is deprecated for audit events as of GitLab 17.8,
		// but keyset is not offered on every endpoint or version.
		q.Set("pagination", "keyset")
		q.Set("order_by", "id")
	}
	q.Set("created_after", since.UTC().Format(time.RFC3339))
	if !st.ceiling.IsZero() {
		q.Set("created_before", st.ceiling.UTC().Format(time.RFC3339))
	}

	reqURL := fmt.Sprintf("%s%s?%s", a.conf.URL, s.path, q.Encode())

	var newest, oldest, firstTs, lastTs time.Time
	nFetched := 0
	truncated := false

	for page := 0; reqURL != "" && !a.doStop.IsSet(); page++ {
		if page >= maxPagesPerCycle {
			truncated = true
			break
		}
		items, next, err := a.makeOneRequest(reqURL)
		if err != nil {
			if errors.Is(err, errKeysetUnsupported) {
				return since, 0, err
			}
			break
		}
		if len(items) == 0 {
			break
		}
		for i, item := range items {
			ts := eventTime(item)
			if page == 0 && i == 0 {
				firstTs = ts
			}
			lastTs = ts
			if newest.IsZero() || ts.After(newest) {
				newest = ts
			}
			if oldest.IsZero() || ts.Before(oldest) {
				oldest = ts
			}
			if a.isDuplicate(s, item) {
				continue
			}
			if !a.ship(s, item, ts) {
				return since, nFetched, nil
			}
			nFetched++
		}
		reqURL = next
	}

	if newest.IsZero() {
		// Nothing came back, so leave the watermark and any drain in place.
		return since, nFetched, nil
	}

	// Newest-first results with more pages outstanding mean the events we have
	// not read yet are OLDER than the ones just shipped. Advancing the
	// watermark would skip them, so cap the next cycle instead and work
	// backwards until the window is drained.
	if truncated && lastTs.Before(firstTs) {
		if st.pendingSince.IsZero() || newest.After(st.pendingSince) {
			st.pendingSince = newest
		}
		st.ceiling = oldest
		a.conf.ClientOptions.OnWarning(fmt.Sprintf("%s: more events than one cycle can read, draining backlog older than %s", s.name, oldest.Format(time.RFC3339)))
		return since, nFetched, nil
	}

	// Window drained. Adopt the highest timestamp seen, including any held
	// back while the backlog was being worked through.
	st.ceiling = time.Time{}
	if st.pendingSince.After(newest) {
		newest = st.pendingSince
	}
	st.pendingSince = time.Time{}

	if newest.After(since) {
		return newest.Add(-overlapPeriod), nFetched, nil
	}
	return since, nFetched, nil
}

// fetchActivityEvents pages through the Events API. That API only filters on
// whole days, so results are read newest first and paging stops as soon as the
// watermark is reached.
func (a *GitLabAdapter) fetchActivityEvents(s stream, since time.Time) (time.Time, int) {
	q := url.Values{}
	q.Set("per_page", strconv.Itoa(pageSize))
	q.Set("sort", "desc")
	// "after" is exclusive and day granular, so step back a day to be sure
	// the whole watermark day is covered.
	q.Set("after", since.UTC().AddDate(0, 0, -1).Format("2006-01-02"))

	reqURL := fmt.Sprintf("%s%s?%s", a.conf.URL, s.path, q.Encode())

	newest := since
	nFetched := 0

	for page := 0; page < maxPagesPerCycle && reqURL != "" && !a.doStop.IsSet(); page++ {
		items, next, err := a.makeOneRequest(reqURL)
		if err != nil {
			break
		}
		if len(items) == 0 {
			break
		}
		reachedWatermark := false
		for _, item := range items {
			ts := eventTime(item)
			if !ts.After(since) {
				reachedWatermark = true
				continue
			}
			if ts.After(newest) {
				newest = ts
			}
			if a.isDuplicate(s, item) {
				continue
			}
			if !a.ship(s, item, ts) {
				return since, nFetched
			}
			nFetched++
		}
		if reachedWatermark {
			break
		}
		reqURL = next
	}

	if newest.After(since) {
		return newest.Add(-overlapPeriod), nFetched
	}
	return since, nFetched
}

func (a *GitLabAdapter) ship(s stream, item utils.Dict, ts time.Time) bool {
	msg := &protocol.DataMessage{
		EventType:   s.eventType,
		JsonPayload: item,
		TimestampMs: uint64(ts.UnixMilli()),
	}
	if err := a.uspClient.Ship(msg, 10*time.Second); err != nil {
		if err == uspclient.ErrorBufferFull {
			a.conf.ClientOptions.OnWarning("stream falling behind")
			err = a.uspClient.Ship(msg, 1*time.Hour)
		}
		if err != nil {
			a.conf.ClientOptions.OnError(fmt.Errorf("Ship(): %v", err))
			a.doStop.Set()
			return false
		}
	}
	return true
}

func (a *GitLabAdapter) isDuplicate(s stream, item utils.Dict) bool {
	id := idKey(item["id"])
	if id == "" {
		// Without an ID there is nothing stable to dedupe on, ship it.
		return false
	}
	return a.dedupe.CheckAndAdd(fmt.Sprintf("%s/%s", s.name, id))
}

// makeOneRequest issues a single page request, retrying the failures that are
// worth retrying. It returns the items and the URL of the next page, if any.
func (a *GitLabAdapter) makeOneRequest(reqURL string) ([]utils.Dict, string, error) {
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		items, next, retryIn, err := a.doRequest(reqURL)
		if err == nil {
			return items, next, nil
		}
		lastErr = err
		if errors.Is(err, errKeysetUnsupported) {
			// Expected on endpoints without keyset support; the caller
			// downgrades and retries rather than treating it as an error.
			return nil, "", err
		}
		if retryIn <= 0 {
			break
		}
		a.conf.ClientOptions.DebugLog(fmt.Sprintf("retrying %s in %v: %v", reqURL, retryIn, err))
		if a.doStop.WaitFor(retryIn * time.Duration(attempt)) {
			break
		}
	}

	a.conf.ClientOptions.OnError(fmt.Errorf("gitlab api: %v", lastErr))
	return nil, "", lastErr
}

// doRequest performs one HTTP request. A returned retryIn greater than zero
// indicates the caller should try again after that delay.
func (a *GitLabAdapter) doRequest(reqURL string) ([]utils.Dict, string, time.Duration, error) {
	a.conf.ClientOptions.DebugLog(fmt.Sprintf("requesting %s", reqURL))

	req, err := http.NewRequestWithContext(a.ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("PRIVATE-TOKEN", a.conf.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, "", baseRetryPeriod, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", baseRetryPeriod, err
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("non-200 (%s) from %s: %s", resp.Status, reqURL, string(body))
		if resp.StatusCode == http.StatusMethodNotAllowed && bytes.Contains(bytes.ToLower(body), []byte("keyset pagination")) {
			return nil, "", 0, fmt.Errorf("%w: %v", errKeysetUnsupported, err)
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, "", retryAfter(resp.Header.Get("Retry-After")), err
		}
		return nil, "", 0, err
	}

	var items []utils.Dict
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, "", 0, fmt.Errorf("invalid json: %v", err)
	}

	return items, a.nextPageURL(resp.Header.Get("Link")), 0, nil
}

// nextPageURL extracts the rel="next" link and rebases it onto the host the
// adapter is configured with, since the instance may advertise a different
// external URL than the one it is reachable on from here. Only the scheme and
// host are replaced, so instances served from a sub-path keep their prefix.
func (a *GitLabAdapter) nextPageURL(linkHeader string) string {
	next := parseNextLink(linkHeader)
	if next == "" {
		return ""
	}
	parsed, err := url.Parse(next)
	if err != nil {
		return ""
	}
	base, err := url.Parse(a.conf.URL)
	if err != nil {
		return ""
	}
	parsed.Scheme = base.Scheme
	parsed.Host = base.Host
	return parsed.String()
}

// parseNextLink pulls the rel="next" URL out of an RFC 5988 Link header.
func parseNextLink(linkHeader string) string {
	for _, link := range strings.Split(linkHeader, ",") {
		parts := strings.Split(link, ";")
		if len(parts) < 2 {
			continue
		}
		isNext := false
		for _, param := range parts[1:] {
			param = strings.TrimSpace(param)
			if param == "rel=\"next\"" || param == "rel=next" {
				isNext = true
				break
			}
		}
		if !isNext {
			continue
		}
		u := strings.TrimSpace(parts[0])
		u = strings.TrimPrefix(u, "<")
		u = strings.TrimSuffix(u, ">")
		if u != "" {
			return u
		}
	}
	return ""
}

func retryAfter(header string) time.Duration {
	if header == "" {
		return baseRetryPeriod
	}
	if seconds, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return baseRetryPeriod
}

// eventTime reads the event's created_at, falling back to the current time so
// that an unparsable record is still shipped with a sane timestamp.
func eventTime(item utils.Dict) time.Time {
	createdAt, _ := item["created_at"].(string)
	if createdAt == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return time.Now().UTC()
	}
	return t.UTC()
}

// idKey renders an event ID as a stable string without altering the payload.
func idKey(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprintf("%v", t)
	}
}
