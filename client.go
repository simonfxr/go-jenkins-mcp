package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// JenkinsOptions bundles configuration for jenkins api calls.
type JenkinsOptions struct {
	URL   string
	Auth  string // format: "user:api_token"; split into User/Token at startup
	User  string
	Token string

	Client     *http.Client // API calls
	LogsClient *http.Client // log and artifact downloads
	Logs       *logStore

	PollInterval time.Duration // build/queue polling interval
	RetryBackoff time.Duration // base backoff for retried GET requests
}

// init prepares HTTP clients and the log store. cacheDir may be empty to
// disable the on-disk log cache; fallbackCacheDir is used when cacheDir
// cannot be written.
func (opts *JenkinsOptions) init(cacheDir, fallbackCacheDir string) {
	jar, _ := cookiejar.New(nil)
	opts.Client = newHTTPClient(30*time.Second, jar)
	opts.LogsClient = newHTTPClient(5*time.Minute, jar)
	opts.Logs = newLogStore(cacheDir, fallbackCacheDir, opts.URL)
	if opts.PollInterval <= 0 {
		opts.PollInterval = 3 * time.Second
	}
	if opts.RetryBackoff <= 0 {
		opts.RetryBackoff = 300 * time.Millisecond
	}
}

// newHTTPClient returns a client that follows redirects for GET/HEAD only.
// Jenkins answers build triggers with 201/302/303 responses whose status and
// Location header carry the outcome, so POST redirects must not be followed.
func newHTTPClient(timeout time.Duration, jar http.CookieJar) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if m := via[0].Method; m != http.MethodGet && m != http.MethodHead {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}
}

// apiError is a non-success HTTP response from Jenkins.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "jenkins rejected the credentials (HTTP 401): check user and API token"
	case http.StatusForbidden:
		return "jenkins denied permission (HTTP 403): " + e.Message
	}
	if e.Message == "" {
		return fmt.Sprintf("jenkins returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("jenkins returned HTTP %d: %s", e.Status, e.Message)
}

// isNotFound reports whether err is a Jenkins 404 response.
func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

var (
	htmlDropRe  = regexp.MustCompile(`(?is)<(script|style|head)\b.*?</(script|style|head)>`)
	htmlTitleRe = regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	htmlTagRe   = regexp.MustCompile(`(?s)<[^>]*>`)
	spaceRe     = regexp.MustCompile(`\s+`)
)

// newAPIError builds an apiError from a response, reducing Jenkins' HTML error
// pages to a short plain-text message.
func newAPIError(resp *http.Response) *apiError {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return &apiError{Status: resp.StatusCode, Message: summarizeErrorBody(body)}
}

func summarizeErrorBody(body []byte) string {
	s := string(body)
	if strings.Contains(s, "<") && strings.Contains(s, ">") {
		title := ""
		if m := htmlTitleRe.FindStringSubmatch(s); m != nil {
			title = strings.TrimSpace(m[1])
		}
		s = htmlDropRe.ReplaceAllString(s, " ")
		s = htmlTagRe.ReplaceAllString(s, " ")
		s = strings.TrimSpace(spaceRe.ReplaceAllString(html.UnescapeString(s), " "))
		if s == "" {
			s = html.UnescapeString(title)
		}
	}
	s = strings.TrimSpace(spaceRe.ReplaceAllString(s, " "))
	const maxLen = 300
	if len(s) > maxLen {
		s = strings.ToValidUTF8(s[:maxLen], "") + "…"
	}
	return s
}

// request executes a Jenkins API request relative to the configured base URL.
// Only relative paths are accepted so credentials are never sent elsewhere.
// GET requests are retried on transport errors and 502/503/504 responses.
func (opts *JenkinsOptions) request(
	ctx context.Context,
	client *http.Client,
	method string,
	apiPath string,
	body []byte,
	headers map[string]string,
) (*http.Response, error) {
	if client == nil {
		client = opts.Client
	}
	fullURL := strings.TrimRight(opts.URL, "/") + "/" + strings.TrimLeft(apiPath, "/")

	attempts := 1
	if method == http.MethodGet {
		attempts = 3
	}
	var lastErr error
	for i := range attempts {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(opts.RetryBackoff << (i - 1)):
			}
		}
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, fullURL, rd)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(opts.User, opts.Token)
		req.Header.Set("Accept", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			continue
		}
		switch resp.StatusCode {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			if i < attempts-1 {
				lastErr = newAPIError(resp)
				resp.Body.Close()
				continue
			}
		}
		return resp, nil
	}
	return nil, fmt.Errorf("jenkins request failed: %w", lastErr)
}

// getJSON performs a GET and decodes a JSON response into out.
func (opts *JenkinsOptions) getJSON(ctx context.Context, apiPath string, out any) error {
	resp, err := opts.request(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return newAPIError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("failed to decode jenkins response: %w", err)
	}
	return nil
}

// post performs a form POST. API tokens are exempt from CSRF protection, so a
// crumb is only fetched (and the request retried once) when Jenkins answers 403.
func (opts *JenkinsOptions) post(ctx context.Context, apiPath string, form url.Values) (*http.Response, error) {
	headers := map[string]string{}
	var body []byte
	if form != nil {
		body = []byte(form.Encode())
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}
	resp, err := opts.request(ctx, opts.Client, http.MethodPost, apiPath, body, headers)
	if err != nil || resp.StatusCode != http.StatusForbidden {
		return resp, err
	}
	field, crumb, ok := opts.getCrumb(ctx)
	if !ok {
		return resp, nil
	}
	resp.Body.Close()
	headers[field] = crumb
	return opts.request(ctx, opts.Client, http.MethodPost, apiPath, body, headers)
}

// getCrumb fetches the Jenkins CSRF crumb and its header field name.
func (opts *JenkinsOptions) getCrumb(ctx context.Context) (field, crumb string, ok bool) {
	var data struct {
		Field string `json:"crumbRequestField"`
		Crumb string `json:"crumb"`
	}
	if err := opts.getJSON(ctx, "/crumbIssuer/api/json", &data); err != nil {
		return "", "", false
	}
	return data.Field, data.Crumb, data.Field != "" && data.Crumb != ""
}
