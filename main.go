package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GetJobsToolArgs are the tool arguments for jenkins_get_jobs.
type GetJobsToolArgs struct {
	// No arguments
}

// GetJobsToolResponse is the result payload for jenkins_get_jobs.
type GetJobsToolResponse struct {
	JobList []Job
}

// GetJobToolArgs are the tool arguments for jenkins_get_job.
type GetJobToolArgs struct {
	Name string `json:"name" jsonschema:"Name of the Jenkins job to retrieve"`
}

// GetJobToolResponse is the detailed job information returned by jenkins_get_job.
type GetJobToolResponse = Job

// GetRunningBuildsToolArgs are the tool arguments for jenkins_get_running_builds.
type GetRunningBuildsToolArgs struct {
	// No arguments
}

// GetRunningBuildsToolResponse contains the list of currently running builds.
type GetRunningBuildsToolResponse struct {
	Builds []RunningBuild `json:"builds"`
	Queued []QueuedBuild  `json:"queuedBuilds,omitempty"`
}

// GetBuildLogsToolArgs are the tool arguments for jenkins_get_build_logs.
type GetBuildLogsToolArgs struct {
	Name        string `json:"job_name" jsonschema:"Name of the Jenkins job"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	Offset      int    `json:"offset,omitempty" jsonschema:"Starting byte offset in the log file (default: 0)" default:"0"`
	Length      int    `json:"length,omitempty" jsonschema:"Maximum number of bytes to retrieve (default: 8192)" default:"8192"`
}

// GetBuildLogsToolResponse is the raw log text returned by jenkins_get_build_logs.
type GetBuildLogsToolResponse = string

// GetBuildLogTailToolArgs are the tool arguments for jenkins_get_build_log_tail.
type GetBuildLogTailToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name of the Jenkins job"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	MaxLength   int    `json:"max_length,omitempty" jsonschema:"Maximum bytes from end of log to retrieve (default: 8192)" default:"8192"`
}

// GetBuildLogTailToolResponse is the tailed log text returned by jenkins_get_build_log_tail.
type GetBuildLogTailToolResponse = string

// StartJobToolArgs are the tool arguments for jenkins_start_job.
type StartJobToolArgs struct {
	JobName    string         `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	Parameters map[string]any `json:"parameters,omitempty" jsonschema:"Optional key/value map of build parameters"`
}

// StartJobToolResponse represents the response from jenkins_start_job
type StartJobToolResponse struct {
	JobName     string `json:"jobName"`
	QueueURL    string `json:"queueUrl,omitempty"`
	BuildURL    string `json:"buildUrl,omitempty"`
	BuildNumber int    `json:"buildNumber,omitempty"`
}

// WaitForRunningBuildToolArgs are the tool arguments for jenkins_wait_for_running_build.
type WaitForRunningBuildToolArgs struct {
	JobName        string `json:"job_name" jsonschema:"Name of the Jenkins job"`
	BuildNumber    int    `json:"build_number" jsonschema:"Build number"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"Maximum time to wait in seconds (default: 600)" default:"600"`
}

// WaitForRunningBuildToolResponse represents the response from jenkins_wait_for_running_build
type WaitForRunningBuildToolResponse struct {
	JobName     string     `json:"jobName"`
	BuildNumber int        `json:"buildNumber"`
	Status      string     `json:"status"`   // "success", "failure", "unstable", "aborted", "timeout"
	Result      string     `json:"result"`   // Jenkins result string (SUCCESS, FAILURE, UNSTABLE, ABORTED, or empty if timeout)
	Duration    DurationMS `json:"duration"` // Total build duration (human-readable)
	WaitTime    DurationMS `json:"waitTime"` // Time spent waiting (human-readable)
	TimedOut    bool       `json:"timedOut"` // Whether the wait operation timed out
}

// BuildLogs describes a slice of a Jenkins build log and related metadata.
type BuildLogs struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	Offset      int    `json:"offset"`
	Length      int    `json:"length"`
	TotalSize   int    `json:"totalSize"`
	HasMore     bool   `json:"hasMore"`
	Logs        string `json:"logs"`
}

// RunningBuild represents a currently running Jenkins build
type RunningBuild struct {
	JobName     string     `json:"jobName"`
	BuildNumber int        `json:"buildNumber"`
	URL         string     `json:"url"`
	StartTime   TimeMS     `json:"startTime"`          // RFC3339 timestamp
	Duration    DurationMS `json:"duration"`           // Current duration (human-readable)
	Progress    *int       `json:"progress,omitempty"` // Progress percentage (if available)
}

// Job represents a Jenkins job with its current status
type Job struct {
	Name         string           `json:"name"`
	URL          string           `json:"url"`
	Color        string           `json:"color"`                  // Jenkins color coding (blue, red, yellow, etc.)
	Buildable    bool             `json:"buildable"`              // Whether the job can be built
	Description  string           `json:"description"`            // Job description
	LastBuild    *Build           `json:"lastBuild,omitempty"`    // Most recent build info
	RecentBuilds []Build          `json:"recentBuilds,omitempty"` // Last 10 builds
	Parameters   []BuildParameter `json:"parameters"`             // Build parameters
	QueuedBuilds []QueuedBuild    `json:"queuedBuilds,omitempty"` // Queued builds for this job
}

// BuildParameter represents a Jenkins build parameter
type BuildParameter struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Description  string   `json:"description"`
	DefaultValue any      `json:"defaultValue"`
	Choices      []string `json:"choices,omitempty"` // For choice parameters
}

// Build represents a Jenkins build
type Build struct {
	Number            int        `json:"number"`
	URL               string     `json:"url"`
	Building          bool       `json:"building"`
	Result            string     `json:"result"`            // SUCCESS, FAILURE, UNSTABLE, ABORTED, null if building
	Timestamp         TimeMS     `json:"timestamp"`         // RFC3339 timestamp
	Duration          DurationMS `json:"duration"`          // Human-readable in output, parses from ms
	EstimatedDuration DurationMS `json:"estimatedDuration"` // Human-readable in output, parses from ms
	DisplayName       string     `json:"displayName"`
}

// QueuedBuild represents a queued Jenkins build item
type QueuedBuild struct {
	JobName     string `json:"jobName"`
	URL         string `json:"url"`
	QueueID     int    `json:"queueId"`
	Why         string `json:"why"`
	QueuedSince TimeMS `json:"queuedSince"`
	Stuck       bool   `json:"stuck"`
	Buildable   bool   `json:"buildable"`
	Parameters  string `json:"parameters,omitempty"`
}

// JenkinsOptions bundles configuration for jenkins api calls.
type JenkinsOptions struct {
	URL        string
	Auth       string // format: "user:api_token" (kept for backward compatibility)
	User       string
	Token      string
	Client     *http.Client
	LogsClient *http.Client
}

func (opts *JenkinsOptions) addTools(s *mcp.Server) {
	addTool(s, &mcp.Tool{
		Name:        "jenkins_get_jobs",
		Description: "Get list of Jenkins jobs with their current status"},
		func(ctx context.Context, req *mcp.CallToolRequest, args GetJobsToolArgs) (*mcp.CallToolResult, GetJobsToolResponse, error) {
			jobs, err := opts.getJenkinsJobs(ctx)
			if err != nil {
				return nil, GetJobsToolResponse{}, err
			}
			return structuredResult(GetJobsToolResponse{jobs})
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_get_job",
		Description: "Get detailed information about a specific Jenkins job by name"},
		func(ctx context.Context, req *mcp.CallToolRequest, args GetJobToolArgs) (*mcp.CallToolResult, Job, error) {
			if strings.TrimSpace(args.Name) == "" {
				return nil, Job{}, fmt.Errorf("missing required argument: name")
			}
			job, err := opts.getJenkinsJob(ctx, args.Name)
			if err != nil {
				return nil, Job{}, err
			}
			return structuredResult(*job)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_get_running_builds",
		Description: "Get list of currently running Jenkins builds"},
		func(ctx context.Context, req *mcp.CallToolRequest, args GetRunningBuildsToolArgs) (*mcp.CallToolResult, GetRunningBuildsToolResponse, error) {
			runningBuilds, err := opts.getRunningBuilds(ctx)
			if err != nil {
				return nil, GetRunningBuildsToolResponse{}, err
			}
			queuedBuilds, err := opts.getQueuedBuilds(ctx)
			if err != nil {
				// Degrade gracefully if queue endpoint is unavailable
				queuedBuilds = nil
			}
			return structuredResult(GetRunningBuildsToolResponse{Builds: runningBuilds, Queued: queuedBuilds})
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_get_build_logs",
		Description: "Get build logs for a specific Jenkins job and build number starting at given offset"},
		func(ctx context.Context, req *mcp.CallToolRequest, args GetBuildLogsToolArgs) (*mcp.CallToolResult, any, error) {
			if strings.TrimSpace(args.Name) == "" {
				return nil, nil, fmt.Errorf("missing required argument: name")
			}
			if args.BuildNumber <= 0 {
				return nil, nil, fmt.Errorf("missing or invalid required argument: build_number (must be > 0)")
			}
			if args.Length <= 0 {
				args.Length = 8192
			}
			// Clamp offset to non-negative using max()
			args.Offset = max(0, args.Offset)
			logsResponse, err := opts.getBuildLogs(ctx, args.Name, args.BuildNumber, args.Offset, args.Length)
			if err != nil {
				return nil, nil, err
			}
			var res mcp.CallToolResult
			res.Content = []mcp.Content{&mcp.TextContent{Text: logsResponse.Logs}}
			return &res, nil, nil
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_get_build_log_tail",
		Description: "Get the tail of build logs for a specific Jenkins job and build number"},
		func(ctx context.Context, req *mcp.CallToolRequest, args GetBuildLogTailToolArgs) (*mcp.CallToolResult, any, error) {
			if strings.TrimSpace(args.JobName) == "" {
				return nil, nil, fmt.Errorf("missing required argument: job_name")
			}
			if args.BuildNumber <= 0 {
				return nil, nil, fmt.Errorf("missing or invalid required argument: build_number (must be > 0)")
			}
			if args.MaxLength <= 0 {
				args.MaxLength = 8192
			}
			logsResponse, err := opts.getBuildLogTail(ctx, args.JobName, args.BuildNumber, args.MaxLength)
			if err != nil {
				return nil, nil, err
			}
			var res mcp.CallToolResult
			res.Content = []mcp.Content{&mcp.TextContent{Text: logsResponse.Logs}}
			return &res, nil, nil
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_start_job",
		Description: "Trigger a Jenkins job build with optional parameters"},
		func(ctx context.Context, req *mcp.CallToolRequest, args StartJobToolArgs) (*mcp.CallToolResult, StartJobToolResponse, error) {
			if strings.TrimSpace(args.JobName) == "" {
				return nil, StartJobToolResponse{}, fmt.Errorf("missing required argument: job_name")
			}
			// Hardcode the behavior to 'queued' (return after getting queue URL)
			resObj, err := opts.startJob(ctx, args.JobName, args.Parameters)
			if err != nil {
				return nil, StartJobToolResponse{}, err
			}
			return structuredResult(*resObj)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_wait_for_running_build",
		Description: "Wait for a running Jenkins build to complete or timeout"},
		func(ctx context.Context, req *mcp.CallToolRequest, args WaitForRunningBuildToolArgs) (*mcp.CallToolResult, WaitForRunningBuildToolResponse, error) {
			if strings.TrimSpace(args.JobName) == "" {
				return nil, WaitForRunningBuildToolResponse{}, fmt.Errorf("missing required argument: job_name")
			}
			if args.BuildNumber <= 0 {
				return nil, WaitForRunningBuildToolResponse{}, fmt.Errorf("missing or invalid required argument: build_number")
			}
			if args.TimeoutSeconds <= 0 {
				args.TimeoutSeconds = 600
			}
			resObj, err := opts.waitForRunningBuild(ctx, args.JobName, args.BuildNumber, args.TimeoutSeconds)
			if err != nil {
				return nil, WaitForRunningBuildToolResponse{}, err
			}
			return structuredResult(*resObj)
		})
}

// buildJobPath builds a Jenkins job path supporting nested folders.
// Example: "folder1/folder2/jobName" -> "/job/folder1/job/folder2/job/jobName"
func buildJobPath(jobName string) string {
	segs := strings.Split(jobName, "/")
	var b strings.Builder
	for _, s := range segs {
		if s == "" {
			continue
		}
		b.WriteString("/job/")
		b.WriteString(url.PathEscape(s))
	}
	return b.String()
}

// callJenkins builds the URL (absolute or relative to base), attaches auth and headers, and executes the request.
// If apiPath starts with http:// or https://, it is treated as an absolute URL; otherwise it is appended to opts.URL.
// Default Accept header is application/json unless overridden via headers.
func (opts *JenkinsOptions) callJenkins(
	ctx context.Context,
	client *http.Client,
	method string,
	apiPath string,
	body io.Reader,
	headers map[string]string,
) (*http.Response, error) {
	if client == nil {
		client = opts.Client
	}
	base := strings.TrimRight(opts.URL, "/")
	var fullURL string
	if strings.HasPrefix(apiPath, "http://") || strings.HasPrefix(apiPath, "https://") {
		fullURL = apiPath
	} else {
		if strings.HasPrefix(apiPath, "/") {
			fullURL = base + apiPath
		} else if apiPath == "" {
			fullURL = base
		} else {
			fullURL = base + "/" + apiPath
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(opts.User, opts.Token)
	if headers == nil {
		headers = map[string]string{}
	}
	if _, ok := headers["Accept"]; !ok {
		req.Header.Set("Accept", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return client.Do(req)
}

// getCrumb fetches Jenkins CSRF crumb and header field name.
func (opts *JenkinsOptions) getCrumb(ctx context.Context) (field, crumb string, ok bool, err error) {
	resp, err := opts.callJenkins(ctx, opts.Client, http.MethodGet, "/crumbIssuer/api/json", nil, nil)
	if err != nil {
		return "", "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Crumbs disabled
		return "", "", false, nil
	}
	if resp.StatusCode != http.StatusOK {
		// Don't fail build start if crumb endpoint errors; treat as no crumb
		return "", "", false, nil
	}
	var data struct {
		Field string `json:"crumbRequestField"`
		Crumb string `json:"crumb"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", false, nil
	}
	if data.Field == "" || data.Crumb == "" {
		return "", "", false, nil
	}
	return data.Field, data.Crumb, true, nil
}

// startJob triggers a Jenkins job, optionally with parameters, and optionally waits.
func (opts *JenkinsOptions) startJob(ctx context.Context, jobName string, params map[string]any) (*StartJobToolResponse, error) {
	jobPath := buildJobPath(jobName)

	// Always use buildWithParameters endpoint as it works for both parameterized and non-parameterized jobs
	apiPath := jobPath + "/buildWithParameters"

	form := url.Values{}
	for k, v := range params {
		form.Set(k, fmt.Sprint(v))
	}
	// If no parameters provided, still send the form (empty is fine for buildWithParameters)

	body := strings.NewReader(form.Encode())

	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if f, c, ok, _ := opts.getCrumb(ctx); ok {
		headers[f] = c
	}
	resp, err := opts.callJenkins(ctx, opts.Client, http.MethodPost, apiPath, body, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to start build: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Capture Location header if present. Jenkins typically returns a queue item URL,
	// but in some cases it may point directly to the build URL if it started immediately.
	loc := resp.Header.Get("Location")
	result := &StartJobToolResponse{JobName: jobName}
	if loc != "" {
		if strings.Contains(loc, "/queue/item/") {
			// Queue URL case
			result.QueueURL = loc
			if queueID := extractQueueID(loc); queueID != "" {
				if buildNumber, buildURL := opts.getQueueItemDetails(ctx, queueID); buildNumber > 0 {
					result.BuildNumber = buildNumber
					result.BuildURL = buildURL
				}
			}
		} else {
			// Likely a direct build URL
			if bn := parseBuildNumberFromURL(loc); bn > 0 {
				result.BuildNumber = bn
				result.BuildURL = loc
			}
		}
	}

	// Hardcoded 'queued' behavior: return immediately after getting queue URL
	return result, nil
}

// extractQueueID extracts queue item ID from queue URL
func extractQueueID(queueURL string) string {
	// Extract ID from URL like "https://jenkins.example.com/queue/item/19069/"
	parts := strings.Split(strings.TrimSuffix(queueURL, "/"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// getQueueItemDetails fetches build number and URL from queue item with retry
func (opts *JenkinsOptions) getQueueItemDetails(ctx context.Context, queueID string) (int, string) {
	apiPath := "/queue/item/" + queueID + "/api/json"

	// Poll up to 60s with arithmetic backoff 1s, 2s, ...
	start := time.Now()
	attempt := 0
	for {
		// Check overall time budget
		if time.Since(start) >= 60*time.Second {
			break
		}

		resp, err := opts.callJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				var queueItem struct {
					ID         int `json:"id"`
					Executable struct {
						Number int    `json:"number"`
						URL    string `json:"url"`
					} `json:"executable"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&queueItem); err == nil {
					resp.Body.Close()
					if queueItem.Executable.Number > 0 {
						return queueItem.Executable.Number, queueItem.Executable.URL
					}
				} else {
					resp.Body.Close()
				}
			} else {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}

		attempt++
		// Compute next sleep using arithmetic backoff
		next := time.Duration(attempt) * time.Second
		remaining := 60*time.Second - time.Since(start)
		if remaining <= 0 {
			break
		}
		if next > remaining {
			next = remaining
		}
		time.Sleep(next)
	}

	return 0, ""
}

// getBuildLogTail fetches the tail of build logs from jenkins api
func (opts *JenkinsOptions) getBuildLogTail(ctx context.Context, jobName string, buildNumber, maxLength int) (*BuildLogs, error) {
	client := opts.LogsClient

	// First, get the total log size to calculate the offset for the tail
	// Build Jenkins job path for nested jobs/folders
	jobPath := buildJobPath(jobName)

	// Get log size using progressiveText API
	sizePath := fmt.Sprintf("%s/%d/logText/progressiveText?start=0", jobPath, buildNumber)
	resp, err := opts.callJenkins(ctx, client, http.MethodGet, sizePath, nil, map[string]string{"Accept": "text/plain"})
	if err != nil {
		return nil, fmt.Errorf("failed to make size request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' build #%d not found", jobName, buildNumber)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, string(body))
	}

	// Get total log size from X-Text-Size header
	totalSize := 0
	if textSizeHeader := resp.Header.Get("X-Text-Size"); textSizeHeader != "" {
		if size, err := strconv.Atoi(textSizeHeader); err == nil {
			totalSize = size
		}
	}

	// If we couldn't get the size from headers, read the response to get an estimate
	if totalSize == 0 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		totalSize = len(body)

		// If the response is small enough, just return it
		if totalSize <= maxLength {
			return &BuildLogs{
				JobName:     jobName,
				BuildNumber: buildNumber,
				Offset:      0,
				Length:      totalSize,
				TotalSize:   totalSize,
				HasMore:     false,
				Logs:        string(body),
			}, nil
		}
	}

	// Calculate offset for the tail, clamping using max/min
	offset := max(0, totalSize-maxLength)
	maxLength = min(maxLength, totalSize)

	// Now get the actual tail logs
	tailPath := fmt.Sprintf("%s/%d/logText/progressiveText?start=%d", jobPath, buildNumber, offset)
	tailResp, err := opts.callJenkins(ctx, client, http.MethodGet, tailPath, nil, map[string]string{"Accept": "text/plain"})
	if err != nil {
		return nil, fmt.Errorf("failed to make tail request: %w", err)
	}
	defer tailResp.Body.Close()

	if tailResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tailResp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", tailResp.StatusCode, string(body))
	}

	// Read the tail logs
	logData, err := io.ReadAll(tailResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read tail response body: %w", err)
	}

	logs := string(logData)

	// Limit the response to the requested length (in case we got more)
	keep := min(len(logs), maxLength)
	logs = logs[len(logs)-keep:]
	offset = totalSize - len(logs)

	// Check if the build is still running
	hasMore := tailResp.Header.Get("X-More-Data") == "true"

	return &BuildLogs{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Offset:      offset,
		Length:      len(logs),
		TotalSize:   totalSize,
		HasMore:     hasMore,
		Logs:        logs,
	}, nil
}

// getBuildLogs fetches build logs from jenkins api with pagination support
func (opts *JenkinsOptions) getBuildLogs(ctx context.Context, jobName string, buildNumber, offset, length int) (*BuildLogs, error) {
	client := opts.LogsClient

	// Build Jenkins job path for nested jobs/folders
	jobPath := buildJobPath(jobName)

	// Build the API URL for build logs with range parameters
	// Jenkins supports HTTP Range headers for log pagination
	apiPath := fmt.Sprintf("%s/%d/logText/progressiveText?start=%d", jobPath, buildNumber, offset)
	resp, err := opts.callJenkins(ctx, client, http.MethodGet, apiPath, nil, map[string]string{"Accept": "text/plain"})
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' build #%d not found", jobName, buildNumber)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read the response body
	logData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Limit the response to the requested length
	logs := string(logData)
	logs = logs[:min(len(logs), length)]

	// Check Jenkins headers for more information
	hasMore := false
	totalSize := offset + len(logData)

	// Jenkins progressive text API provides X-Text-Size header with total log size
	if textSizeHeader := resp.Header.Get("X-Text-Size"); textSizeHeader != "" {
		if size, err := strconv.Atoi(textSizeHeader); err == nil {
			totalSize = size
			hasMore = offset+len(logs) < totalSize
		}
	} else {
		// If no header, assume there might be more if we got exactly what we asked for
		hasMore = len(logData) > 0 && len(logs) == length
	}

	// Check if the build is still running (X-More-Data header)
	if resp.Header.Get("X-More-Data") == "true" {
		hasMore = true
	}

	return &BuildLogs{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Offset:      offset,
		Length:      len(logs),
		TotalSize:   totalSize,
		HasMore:     hasMore,
		Logs:        logs,
	}, nil
}

// getJenkinsJob fetches a specific job from jenkins api by name
func (opts *JenkinsOptions) getJenkinsJob(ctx context.Context, jobName string) (*Job, error) {
	client := opts.Client

	// Build Jenkins job path for nested jobs/folders
	jobPath := buildJobPath(jobName)

	// Build the API URL for the specific job with expanded parameter information
	apiPath := jobPath + "/api/json?tree=" +
		"name,url,color,buildable,description," +
		"lastBuild[" +
		"number,url,building,result,timestamp,duration,estimatedDuration,displayName" +
		"]," +
		"builds[" +
		"number,url,building,result,timestamp,duration,estimatedDuration,displayName" +
		"]{0,10}," +
		"property[parameterDefinitions[name,type,description,defaultParameterValue[value],choices]]"
	resp, err := opts.callJenkins(ctx, client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' not found", jobName)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var jobData struct {
		Name        string  `json:"name"`
		URL         string  `json:"url"`
		Color       string  `json:"color"`
		Buildable   bool    `json:"buildable"`
		Description string  `json:"description"`
		LastBuild   *Build  `json:"lastBuild"`
		Builds      []Build `json:"builds"`
		Property    []struct {
			ParameterDefinitions []struct {
				Name                  string `json:"name"`
				Type                  string `json:"type"`
				Description           string `json:"description"`
				DefaultParameterValue *struct {
					Value any `json:"value"`
				} `json:"defaultParameterValue"`
				Choices []string `json:"choices"`
			} `json:"parameterDefinitions"`
		} `json:"property"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jobData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert builds to our format
	recentBuilds := make([]Build, len(jobData.Builds))
	for i, buildData := range jobData.Builds {
		recentBuilds[i] = Build(buildData)
	}

	// Convert to our format
	jenkinsJob := &Job{
		Name:         jobData.Name,
		URL:          jobData.URL,
		Color:        jobData.Color,
		Buildable:    jobData.Buildable,
		Description:  jobData.Description,
		RecentBuilds: recentBuilds,
		Parameters:   []BuildParameter{},
	}

	// Extract build parameters from properties
	for _, property := range jobData.Property {
		for _, paramDef := range property.ParameterDefinitions {
			param := BuildParameter{
				Name:        paramDef.Name,
				Type:        paramDef.Type,
				Description: paramDef.Description,
				Choices:     paramDef.Choices,
			}

			// Extract default value if present
			if paramDef.DefaultParameterValue != nil {
				param.DefaultValue = paramDef.DefaultParameterValue.Value
			}

			jenkinsJob.Parameters = append(jenkinsJob.Parameters, param)
		}
	}

	// Sort recentBuilds by build number (descending - most recent first)
	sort.Slice(recentBuilds, func(i, j int) bool {
		return recentBuilds[i].Number > recentBuilds[j].Number
	})

	// Include queued builds that match this job (by URL prefix)
	if queuedAll, err := opts.getQueuedBuilds(ctx); err == nil {
		for _, qb := range queuedAll {
			if strings.HasPrefix(qb.URL, jenkinsJob.URL) {
				jenkinsJob.QueuedBuilds = append(jenkinsJob.QueuedBuilds, qb)
			}
		}
	}

	return jenkinsJob, nil
}

// getJenkinsJobs fetches jobs from jenkins api
func (opts *JenkinsOptions) getJenkinsJobs(ctx context.Context) ([]Job, error) {
	client := opts.Client

	// Build the API URL
	resp, err := opts.callJenkins(ctx, client, http.MethodGet, "/api/json?tree="+
		"jobs["+
		"name,url,color,buildable,description,"+
		"lastBuild[number,url,building,result,timestamp,duration,estimatedDuration,displayName]"+
		"]", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp struct {
		Jobs []Job `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return apiResp.Jobs, nil
}

// getBuildDetails fetches detailed information about a specific build
func (opts *JenkinsOptions) getBuildDetails(ctx context.Context, buildURL string) (*Build, error) {
	// Add /api/json to the build URL if not already present
	apiURL := strings.TrimRight(buildURL, "/") + "/api/json"
	resp, err := opts.callJenkins(ctx, opts.Client, http.MethodGet, apiURL, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var buildData Build

	if err := json.NewDecoder(resp.Body).Decode(&buildData); err != nil {
		return nil, err
	}

	return &buildData, nil
}

// getRunningBuilds fetches currently running builds from jenkins api
func (opts *JenkinsOptions) getRunningBuilds(ctx context.Context) ([]RunningBuild, error) {
	client := opts.Client

	// Build the API URL for computer information (includes executors)
	resp, err := opts.callJenkins(ctx, client, http.MethodGet, "/computer/api/json?tree=computer[displayName,executors[currentExecutable[url,fullDisplayName,timestamp],idle,likelyStuck,progress]]", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var computerResp struct {
		Computer []struct {
			DisplayName string `json:"displayName"`
			Executors   []struct {
				CurrentExecutable *struct {
					URL             string `json:"url"`
					FullDisplayName string `json:"fullDisplayName"`
					Timestamp       int64  `json:"timestamp"`
				} `json:"currentExecutable"`
				Idle        bool `json:"idle"`
				LikelyStuck bool `json:"likelyStuck"`
				Progress    *int `json:"progress,omitempty"`
			} `json:"executors"`
		} `json:"computer"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&computerResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var runningBuilds []RunningBuild
	currentTime := time.Now().UnixMilli()

	// Process each computer and its executors
	for _, computer := range computerResp.Computer {
		for _, executor := range computer.Executors {
			// Skip idle executors
			if executor.Idle || executor.CurrentExecutable == nil {
				continue
			}

			executable := executor.CurrentExecutable

			// Parse job name and build number from the full display name
			// Format is typically "jobName #buildNumber"; fallback to URL if needed
			jobName, buildNumber := parseJobNameAndBuildNumber(executable.FullDisplayName)
			if buildNumber == 0 {
				if n := parseBuildNumberFromURL(executable.URL); n > 0 {
					buildNumber = n
				}
			}

			// Compute human-friendly duration from ms and RFC3339 start time
			durMs := currentTime - executable.Timestamp
			startTime := time.Unix(0, executable.Timestamp*int64(time.Millisecond))
			runningBuild := RunningBuild{
				JobName:     jobName,
				BuildNumber: buildNumber,
				URL:         executable.URL,
				StartTime:   TimeMS(startTime),
				Duration:    DurationMS(time.Duration(durMs) * time.Millisecond),
				Progress:    executor.Progress,
			}

			runningBuilds = append(runningBuilds, runningBuild)
		}
	}

	return runningBuilds, nil
}

// getQueuedBuilds fetches queued builds from Jenkins queue API
func (opts *JenkinsOptions) getQueuedBuilds(ctx context.Context) ([]QueuedBuild, error) {
	client := opts.Client
	resp, err := opts.callJenkins(ctx, client, http.MethodGet, "/queue/api/json?tree=items[id,task[name,url],why,inQueueSince,stuck,buildable,params]", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, string(body))
	}

	var queueResp struct {
		Items []struct {
			ID   int `json:"id"`
			Task struct {
				Name string `json:"name"`
				URL  string `json:"url"`
			} `json:"task"`
			Why          string `json:"why"`
			InQueueSince int64  `json:"inQueueSince"`
			Stuck        bool   `json:"stuck"`
			Buildable    bool   `json:"buildable"`
			Params       string `json:"params"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&queueResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	queued := make([]QueuedBuild, 0, len(queueResp.Items))
	for _, it := range queueResp.Items {
		qb := QueuedBuild{
			JobName:     it.Task.Name,
			URL:         it.Task.URL,
			QueueID:     it.ID,
			Why:         it.Why,
			QueuedSince: TimeMS(time.Unix(0, it.InQueueSince*int64(time.Millisecond))),
			Stuck:       it.Stuck,
			Buildable:   it.Buildable,
			Parameters:  strings.TrimSpace(it.Params),
		}
		queued = append(queued, qb)
	}
	return queued, nil
}

// waitForRunningBuild waits for a Jenkins build to complete or timeout
func (opts *JenkinsOptions) waitForRunningBuild(ctx context.Context, jobName string, buildNumber, timeoutSeconds int) (*WaitForRunningBuildToolResponse, error) {
	startTime := time.Now()
	timeout := time.Duration(timeoutSeconds) * time.Second
	pollInterval := 5 * time.Second // Poll every 5 seconds

	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build the build URL
	jobPath := buildJobPath(jobName)
	buildURL := fmt.Sprintf("%s%s/%d", strings.TrimRight(opts.URL, "/"), jobPath, buildNumber)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCtx.Done():
			// Timeout occurred
			waitTime := time.Since(startTime)
			return &WaitForRunningBuildToolResponse{
				JobName:     jobName,
				BuildNumber: buildNumber,
				Status:      "timeout",
				Result:      "",
				Duration:    DurationMS(0),
				WaitTime:    DurationMS(waitTime),
				TimedOut:    true,
			}, nil

		case <-ticker.C:
			// Poll the build status
			build, err := opts.getBuildDetails(ctx, buildURL)
			if err != nil {
				// If we can't get build details, continue polling
				// This might happen if the build hasn't started yet
				continue
			}

			// Check if build is complete
			if !build.Building {
				waitTime := time.Since(startTime)

				// Map Jenkins result to our status
				var status string
				switch build.Result {
				case "SUCCESS":
					status = "success"
				case "FAILURE":
					status = "failure"
				case "UNSTABLE":
					status = "unstable"
				case "ABORTED":
					status = "aborted"
				default:
					status = "unknown"
				}

				return &WaitForRunningBuildToolResponse{
					JobName:     jobName,
					BuildNumber: buildNumber,
					Status:      status,
					Result:      build.Result,
					Duration:    build.Duration,
					WaitTime:    DurationMS(waitTime),
					TimedOut:    false,
				}, nil
			}
		}
	}
}

// parseJobNameAndBuildNumber extracts job name and build number from Jenkins full display name
func parseJobNameAndBuildNumber(fullDisplayName string) (string, int) {
	// Try to find the pattern "jobName #buildNumber"
	parts := strings.Split(fullDisplayName, " #")
	if len(parts) == 2 {
		jobName := parts[0]
		buildNumberStr := parts[1]

		// Try to parse the build number
		var buildNumber int
		if _, err := fmt.Sscanf(buildNumberStr, "%d", &buildNumber); err == nil {
			return jobName, buildNumber
		}
	}

	// If parsing fails, return the full name as job name and 0 as build number
	return fullDisplayName, 0
}

// parseBuildNumberFromURL extracts the trailing numeric segment from a Jenkins build URL.
func parseBuildNumberFromURL(u string) int {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	if i := strings.IndexByte(u, '#'); i >= 0 {
		u = u[:i]
	}
	parts := strings.Split(strings.TrimSuffix(u, "/"), "/")
	if len(parts) == 0 {
		return 0
	}
	last := parts[len(parts)-1]
	n, err := strconv.Atoi(last)
	if err != nil {
		return 0
	}
	return n
}

func addTool[In, Out any](s *mcp.Server, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	t.InputSchema = jsonschemaForExt[In]()
	mcp.AddTool(s, t, h)
}

func structuredResult[Out any](out Out) (*mcp.CallToolResult, Out, error) {
	b, err := json.Marshal(out)
	if err != nil {
		var zero Out
		return nil, zero, err
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(b)}},
		StructuredContent: out,
	}, out, nil
}

func main() {
	// Prepare options and bind flags directly to fields.
	opts := &JenkinsOptions{}
	var (
		httpAddr string
		useStdio bool
	)

	flag.StringVar(&opts.URL, "url", "", "Jenkins URL (required)")
	flag.StringVar(&opts.Auth, "auth", "", "Jenkins authentication in format 'user:api_token' (optional if JENKINS_MCP_AUTH env var is set)")
	flag.StringVar(&httpAddr, "http", "", "if set, use streamable HTTP at this address, instead of stdin/stdout")
	flag.BoolVar(&useStdio, "stdio", true, "use stdio transport (ignored if -http is set)")
	flag.Parse()

	// Validate required parameters
	if opts.URL == "" {
		fmt.Fprintln(os.Stderr, "Error: -url parameter is required")
		os.Exit(1)
	}

	// Use environment variable if -auth flag is not provided
	if opts.Auth == "" {
		if envAuth := os.Getenv("JENKINS_MCP_AUTH"); envAuth != "" {
			opts.Auth = envAuth
		} else {
			fmt.Fprintln(os.Stderr, "Error: authentication required via -auth parameter or JENKINS_MCP_AUTH environment variable")
			os.Exit(1)
		}
	}

	// Validate auth format
	if !strings.Contains(opts.Auth, ":") {
		fmt.Fprintln(os.Stderr, "Error: -auth must be in format 'user:api_token'")
		os.Exit(1)
	}

	// Parse user/token and initialize HTTP clients
	parts := strings.SplitN(opts.Auth, ":", 2)
	opts.User, opts.Token = parts[0], parts[1]
	opts.Client = &http.Client{Timeout: 30 * time.Second}
	opts.LogsClient = &http.Client{Timeout: 60 * time.Second}

	log.Printf("Using Jenkins URL: %s", opts.URL)
	log.Printf("Using Jenkins auth for user: %s", strings.Split(opts.Auth, ":")[0])

	// Build MCP server
	server := mcp.NewServer(&mcp.Implementation{Name: "jenkins-mcp-go", Version: "0.1.0"}, nil)

	opts.addTools(server)

	// Choose transport
	if httpAddr != "" {
		handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server { return server }, nil)
		log.Printf("Starting MCP HTTP server on %s", httpAddr)
		if err := http.ListenAndServe(httpAddr, handler); err != nil {
			log.Fatalf("http server error: %v", err)
		}
	} else if useStdio {
		log.Printf("Starting MCP server over stdio")
		t := &mcp.LoggingTransport{Transport: &mcp.StdioTransport{}, Writer: os.Stderr}
		if err := server.Run(context.Background(), t); err != nil {
			log.Printf("server error: %v", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: no transport selected. Use -http or -stdio.")
		os.Exit(1)
	}
}

// DurationMS is a JSON-friendly duration that unmarshals from milliseconds (number)
// and marshals to a human-readable string (e.g., "5m10s").
type DurationMS time.Duration

// UnmarshalJSON parses a duration from milliseconds or string into DurationMS.
func (d *DurationMS) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*d = 0
		return nil
	}
	var ms int64
	if err := json.Unmarshal(b, &ms); err == nil {
		*d = DurationMS(time.Duration(ms) * time.Millisecond)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if dur, err := time.ParseDuration(s); err == nil {
			*d = DurationMS(dur)
			return nil
		}
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			*d = DurationMS(time.Duration(v) * time.Millisecond)
			return nil
		}
	}
	return fmt.Errorf("invalid duration value: %s", string(b))
}

// MarshalJSON encodes DurationMS as a human-readable string (e.g., "5m10s").
func (d DurationMS) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// TimeMS is a JSON-friendly time that unmarshals from milliseconds-since-epoch (number)
// and marshals to an RFC3339 timestamp string (UTC).
type TimeMS time.Time

// UnmarshalJSON parses a timestamp from milliseconds or RFC3339 string into TimeMS.
func (t *TimeMS) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*t = TimeMS(time.Time{})
		return nil
	}
	// Try numeric milliseconds
	var ms int64
	if err := json.Unmarshal(b, &ms); err == nil {
		sec := ms / 1000
		nsec := (ms % 1000) * int64(time.Millisecond)
		*t = TimeMS(time.Unix(sec, nsec))
		return nil
	}
	// Try string timestamp
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			*t = TimeMS(time.Time{})
			return nil
		}
		if parsed, err := time.Parse(time.RFC3339Nano, s); err == nil {
			*t = TimeMS(parsed)
			return nil
		}
		if parsed, err := time.Parse(time.RFC3339, s); err == nil {
			*t = TimeMS(parsed)
			return nil
		}
		if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
			sec := ms / 1000
			nsec := (ms % 1000) * int64(time.Millisecond)
			*t = TimeMS(time.Unix(sec, nsec))
			return nil
		}
	}
	return fmt.Errorf("invalid timestamp value: %s", string(b))
}

// MarshalJSON encodes TimeMS as an RFC3339 UTC timestamp string.
func (t TimeMS) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(tt.UTC().Format(time.RFC3339))
}
