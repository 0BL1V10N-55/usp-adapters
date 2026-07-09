package usp_huntress

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPError represents a non-2xx response from the Huntress API. It carries
// the status code so callers can classify the error (retry vs. give up)
// without having to parse error strings.
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
// Transient (retry):
//   - HTTP 5xx server errors
//   - HTTP 429 Too Many Requests (Huntress rate-limits to 60 req/min per account)
//   - network errors (timeouts, connection refused, DNS failures, ...)
//
// Permanent (do not retry):
//   - HTTP 4xx other than 429 (bad request, auth failure, not found, ...)
//   - context cancellation (intentional shutdown)
func isTransientError(err error) bool {
	if err == nil {
		return false
	}

	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		if httpErr.StatusCode >= 500 && httpErr.StatusCode <= 599 {
			return true
		}
		if httpErr.StatusCode == http.StatusTooManyRequests {
			return true
		}
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	if strings.Contains(err.Error(), "failed to execute request") {
		return true
	}

	return false
}

// HuntressClient is a thin wrapper around the Huntress REST API
// (https://api.huntress.io/v1). The API is uniform: every listable resource
// is a GET returning a JSON object with a plural key for the records and a
// "pagination" key carrying a "next_page_token" for cursor-based paging.
type HuntressClient struct {
	baseURL    string
	authHeader string
	httpClient *http.Client
}

// NewHuntressClient builds a client. baseURL is the API root, e.g.
// "https://api.huntress.io/v1". apiKey/apiSecret are the public/private key
// pair generated under Account > API Credentials in the Huntress portal.
func NewHuntressClient(baseURL, apiKey, apiSecret string) *HuntressClient {
	creds := base64.StdEncoding.EncodeToString([]byte(apiKey + ":" + apiSecret))
	return &HuntressClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		authHeader: "Basic " + creds,
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

// Get issues a GET to the given API path with a query string and returns the
// raw response body. A non-200 response is returned as an *HTTPError.
func (c *HuntressClient) Get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	reqURL := c.baseURL + "/" + strings.TrimPrefix(path, "/")
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request %q: %v", reqURL, err)
	}

	// Huntress authenticates with HTTP Basic access authentication: a
	// Base64-encoded "api_key:api_secret" string in the Authorization header.
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request %q: %v", reqURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response %q: %v", reqURL, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{
			StatusCode: resp.StatusCode,
			URL:        reqURL,
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// Close releases idle connections held by the underlying transport.
func (c *HuntressClient) Close() {
	c.httpClient.CloseIdleConnections()
}
