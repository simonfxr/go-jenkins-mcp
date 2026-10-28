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
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = ""

func getVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

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
	Name      string `json:"name" jsonschema:"Name of the Jenkins job to retrieve"`
	MaxBuilds int    `json:"max_builds,omitempty" jsonschema:"Maximum number of recent builds to return (default: 20)" default:"20"`
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

// GetBuildLogsToolResponse is the build log payload returned by jenkins_get_build_logs.
type GetBuildLogsToolResponse = BuildLogs

// GetBuildToolArgs are the tool arguments for jenkins_get_build.
type GetBuildToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
}

// GetBuildToolResponse is the build payload returned by jenkins_get_build.
type GetBuildToolResponse = Build

// GetBuildLogTailToolArgs are the tool arguments for jenkins_get_build_log_tail.
type GetBuildLogTailToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name of the Jenkins job"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number"`
	MaxLength   int    `json:"max_length,omitempty" jsonschema:"Maximum bytes from end of log to retrieve (default: 8192)" default:"8192"`
}

// GetBuildLogTailToolResponse is the tailed build log payload returned by jenkins_get_build_log_tail.
type GetBuildLogTailToolResponse = BuildLogs

// StartJobToolArgs are the tool arguments for jenkins_start_job.
type StartJobToolArgs struct {
	JobName    string         `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	Parameters map[string]any `json:"parameters,omitempty" jsonschema:"Optional key/value map of build parameters"`
}

// StartJobToolResponse represents the response from jenkins_start_job
type StartJobToolResponse struct {
	JobName     string `json:"jobName"`
	QueueURL    string `json:"queueUrl,omitempty"`
	QueueID     int    `json:"queueId,omitempty"`
	BuildURL    string `json:"buildUrl,omitempty"`
	BuildNumber int    `json:"buildNumber,omitempty"`
}

// GetQueueItemToolArgs are the tool arguments for jenkins_get_queue_item.
type GetQueueItemToolArgs struct {
	QueueID int `json:"queue_id" jsonschema:"Jenkins queue item ID"`
}

// QueueItem represents a Jenkins queue item.
type QueueItem struct {
	QueueID     int    `json:"queueId"`
	JobName     string `json:"jobName,omitempty"`
	URL         string `json:"url,omitempty"`
	Why         string `json:"why,omitempty"`
	QueuedSince TimeMS `json:"queuedSince"`
	Stuck       bool   `json:"stuck,omitempty"`
	Buildable   bool   `json:"buildable,omitempty"`
	Parameters  string `json:"parameters,omitempty"`
	Cancelled   bool   `json:"cancelled,omitempty"`
	Executable  *Build `json:"executable,omitempty"`
}

// WaitForQueueItemToolArgs are the tool arguments for jenkins_wait_for_queue_item.
type WaitForQueueItemToolArgs struct {
	QueueID         int `json:"queue_id" jsonschema:"Jenkins queue item ID"`
	TimeoutSeconds  int `json:"timeout_seconds,omitempty" jsonschema:"Maximum time to wait in seconds (default: 30)" default:"30"`
	PollIntervalSec int `json:"poll_interval_seconds,omitempty" jsonschema:"Polling interval in seconds (default: 2)" default:"2"`
}

// WaitForQueueItemToolResponse represents the response from jenkins_wait_for_queue_item.
type WaitForQueueItemToolResponse struct {
	QueueItem *QueueItem `json:"queueItem,omitempty"`
	Build     *Build     `json:"build,omitempty"`
	WaitTime  DurationMS `json:"waitTime"`
	TimedOut  bool       `json:"timedOut"`
	Status    string     `json:"status"`
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

// StopBuildToolArgs are the tool arguments for jenkins_stop_build.
type StopBuildToolArgs struct {
	JobName     string `json:"job_name" jsonschema:"Name/path of the Jenkins job (supports folders)"`
	BuildNumber int    `json:"build_number" jsonschema:"Build number to stop"`
}

// SearchBuildsToolArgs are the tool arguments for jenkins_search_builds.
type SearchBuildsToolArgs struct {
	JobName     string   `json:"job_name" jsonschema:"Name of the Jenkins job"`
	Result      string   `json:"result,omitempty" jsonschema:"Filter by build result: SUCCESS, FAILURE, ABORTED"`
	Params      []string `json:"params,omitempty" jsonschema:"Filter by build parameters as key=value pairs. Empty value (key=) matches empty/unset parameter."`
	Limit       int      `json:"limit,omitempty" jsonschema:"Maximum number of matching results to return (default: 5)" default:"5"`
	MaxLookback int      `json:"max_lookback,omitempty" jsonschema:"Maximum number of builds to scan (default: 100)" default:"100"`
}

// SearchBuildsToolResponse is the result payload for jenkins_search_builds.
type SearchBuildsToolResponse struct {
	Builds  []Build `json:"builds"`
	Scanned int     `json:"scanned"` // how many builds were scanned
}

// StopBuildToolResponse represents the response from jenkins_stop_build.
type StopBuildToolResponse struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	Stopped     bool   `json:"stopped"`
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
	RecentBuilds []Build          `json:"recentBuilds,omitempty"` // Most recent builds (up to max_builds), newest first
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
	Number            int               `json:"number"`
	URL               string            `json:"url"`
	Building          bool              `json:"building"`
	Result            string            `json:"result"`            // SUCCESS, FAILURE, UNSTABLE, ABORTED, null if building
	Timestamp         TimeMS            `json:"timestamp"`         // RFC3339 timestamp
	Duration          DurationMS        `json:"duration"`          // Human-readable in output, parses from ms
	EstimatedDuration DurationMS        `json:"estimatedDuration"` // Human-readable in output, parses from ms
	DisplayName       string            `json:"displayName"`
	Parameters        map[string]string `json:"parameters,omitempty"` // Build parameters (name -> value)
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
	Auth       string // format: "user:api_token"; split into User/Token at startup
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
			if args.MaxBuilds <= 0 {
				args.MaxBuilds = 20
			}
			job, err := opts.getJenkinsJob(ctx, args.Name, args.MaxBuilds)
			if err != nil {
				return nil, Job{}, err
			}
			return structuredResult(*job)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_get_running_builds",
		Description: "Get list of currently running and queued Jenkins builds"},
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
		Name:        "jenkins_get_build",
		Description: "Get detailed information about a specific Jenkins build by job name and build number"},
		func(ctx context.Context, req *mcp.CallToolRequest, args GetBuildToolArgs) (*mcp.CallToolResult, GetBuildToolResponse, error) {
			if strings.TrimSpace(args.JobName) == "" {
				return nil, GetBuildToolResponse{}, fmt.Errorf("missing required argument: job_name")
			}
			if args.BuildNumber <= 0 {
				return nil, GetBuildToolResponse{}, fmt.Errorf("missing or invalid required argument: build_number (must be > 0)")
			}
			build, err := opts.getBuildDetailsByJob(ctx, args.JobName, args.BuildNumber)
			if err != nil {
				return nil, GetBuildToolResponse{}, err
			}
			return structuredResult(*build)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_get_build_logs",
		Description: "Get build logs for a specific Jenkins job and build number starting at given offset"},
		func(ctx context.Context, req *mcp.CallToolRequest, args GetBuildLogsToolArgs) (*mcp.CallToolResult, GetBuildLogsToolResponse, error) {
			if strings.TrimSpace(args.Name) == "" {
				return nil, GetBuildLogsToolResponse{}, fmt.Errorf("missing required argument: job_name")
			}
			if args.BuildNumber <= 0 {
				return nil, GetBuildLogsToolResponse{}, fmt.Errorf("missing or invalid required argument: build_number (must be > 0)")
			}
			if args.Length <= 0 {
				args.Length = 8192
			}
			args.Offset = max(0, args.Offset)
			logsResponse, err := opts.getBuildLogs(ctx, args.Name, args.BuildNumber, args.Offset, args.Length)
			if err != nil {
				return nil, GetBuildLogsToolResponse{}, err
			}
			return structuredResult(*logsResponse)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_get_build_log_tail",
		Description: "Get the tail of build logs for a specific Jenkins job and build number"},
		func(ctx context.Context, req *mcp.CallToolRequest, args GetBuildLogTailToolArgs) (*mcp.CallToolResult, GetBuildLogTailToolResponse, error) {
			if strings.TrimSpace(args.JobName) == "" {
				return nil, GetBuildLogTailToolResponse{}, fmt.Errorf("missing required argument: job_name")
			}
			if args.BuildNumber <= 0 {
				return nil, GetBuildLogTailToolResponse{}, fmt.Errorf("missing or invalid required argument: build_number (must be > 0)")
			}
			if args.MaxLength <= 0 {
				args.MaxLength = 8192
			}
			logsResponse, err := opts.getBuildLogTail(ctx, args.JobName, args.BuildNumber, args.MaxLength)
			if err != nil {
				return nil, GetBuildLogTailToolResponse{}, err
			}
			return structuredResult(*logsResponse)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_start_job",
		Description: "Trigger a Jenkins job build with optional parameters"},
		func(ctx context.Context, req *mcp.CallToolRequest, args StartJobToolArgs) (*mcp.CallToolResult, StartJobToolResponse, error) {
			if strings.TrimSpace(args.JobName) == "" {
				return nil, StartJobToolResponse{}, fmt.Errorf("missing required argument: job_name")
			}
			resObj, err := opts.startJob(ctx, args.JobName, args.Parameters)
			if err != nil {
				return nil, StartJobToolResponse{}, err
			}
			return structuredResult(*resObj)
		})
	addTool(s, &mcp.Tool{
		Name:        "jenkins_get_queue_item",
		Description: "Get the current state of a Jenkins queue item, including the assigned build when available"},
		func(ctx context.Context, req *mcp.CallToolRequest, args GetQueueItemToolArgs) (*mcp.CallToolResult, QueueItem, error) {
			if args.QueueID <= 0 {
				return nil, QueueItem{}, fmt.Errorf("missing or invalid required argument: queue_id (must be > 0)")
			}
			item, err := opts.getQueueItem(ctx, args.QueueID)
			if err != nil {
				return nil, QueueItem{}, err
			}
			return structuredResult(*item)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_wait_for_queue_item",
		Description: "Wait for a Jenkins queue item to receive a build assignment, be cancelled, or timeout"},
		func(ctx context.Context, req *mcp.CallToolRequest, args WaitForQueueItemToolArgs) (*mcp.CallToolResult, WaitForQueueItemToolResponse, error) {
			if args.QueueID <= 0 {
				return nil, WaitForQueueItemToolResponse{}, fmt.Errorf("missing or invalid required argument: queue_id (must be > 0)")
			}
			if args.TimeoutSeconds <= 0 {
				args.TimeoutSeconds = 30
			}
			if args.PollIntervalSec <= 0 {
				args.PollIntervalSec = 2
			}
			res, err := opts.waitForQueueItem(ctx, args.QueueID, args.TimeoutSeconds, args.PollIntervalSec)
			if err != nil {
				return nil, WaitForQueueItemToolResponse{}, err
			}
			return structuredResult(*res)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_search_builds",
		Description: "Search Jenkins builds by result and/or build parameters. Use to find e.g. the latest successful ARM build or a build without a specific feature branch."},

		func(ctx context.Context, req *mcp.CallToolRequest, args SearchBuildsToolArgs) (*mcp.CallToolResult, SearchBuildsToolResponse, error) {
			if strings.TrimSpace(args.JobName) == "" {
				return nil, SearchBuildsToolResponse{}, fmt.Errorf("missing required argument: job_name")
			}
			if args.Limit <= 0 {
				args.Limit = 5
			}
			if args.MaxLookback <= 0 {
				args.MaxLookback = 100
			}
			res, err := opts.searchBuilds(ctx, args)
			if err != nil {
				return nil, SearchBuildsToolResponse{}, err
			}
			return structuredResult(*res)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_stop_build",
		Description: "Stop a running Jenkins build by job name and build number"},
		func(ctx context.Context, req *mcp.CallToolRequest, args StopBuildToolArgs) (*mcp.CallToolResult, StopBuildToolResponse, error) {
			if strings.TrimSpace(args.JobName) == "" {
				return nil, StopBuildToolResponse{}, fmt.Errorf("missing required argument: job_name")
			}
			if args.BuildNumber <= 0 {
				return nil, StopBuildToolResponse{}, fmt.Errorf("missing or invalid required argument: build_number (must be > 0)")
			}
			resObj, err := opts.stopBuild(ctx, args.JobName, args.BuildNumber)
			if err != nil {
				return nil, StopBuildToolResponse{}, err
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

// startJob triggers a Jenkins job, optionally with parameters, and waits briefly
// (bounded to 30s) for the queue item to be assigned a build number.
func (opts *JenkinsOptions) startJob(ctx context.Context, jobName string, params map[string]any) (*StartJobToolResponse, error) {
	jobPath := buildJobPath(jobName)

	// Always use buildWithParameters endpoint as it works for both parameterized and non-parameterized jobs
	apiPath := jobPath + "/buildWithParameters"

	form := url.Values{}
	for k, v := range params {
		form.Set(k, fmt.Sprint(v))
	}
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
			if queueID := extractQueueID(loc); queueID > 0 {
				result.QueueID = queueID
				if buildNumber, buildURL := opts.getQueueItemDetails(ctx, queueID, 30*time.Second); buildNumber > 0 {
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

	return result, nil
}

// extractQueueID extracts queue item ID from queue URL.
func extractQueueID(queueURL string) int {
	parts := strings.Split(strings.TrimSuffix(queueURL, "/"), "/")
	if len(parts) == 0 {
		return 0
	}
	queueID, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return 0
	}
	return queueID
}

// getQueueItem fetches a Jenkins queue item by ID.
func (opts *JenkinsOptions) getQueueItem(ctx context.Context, queueID int) (*QueueItem, error) {
	apiPath := fmt.Sprintf("/queue/item/%d/api/json?tree=id,task[name,url],why,inQueueSince,stuck,buildable,params,cancelled,executable[number,url,building,result,timestamp,duration,estimatedDuration,displayName]", queueID)

	resp, err := opts.callJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch queue item: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("queue item #%d not found", queueID)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var data struct {
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
		Cancelled    bool   `json:"cancelled"`
		Executable   *Build `json:"executable"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode queue item response: %w", err)
	}

	item := &QueueItem{
		QueueID:     data.ID,
		JobName:     data.Task.Name,
		URL:         data.Task.URL,
		Why:         data.Why,
		QueuedSince: TimeMS(time.Unix(0, data.InQueueSince*int64(time.Millisecond))),
		Stuck:       data.Stuck,
		Buildable:   data.Buildable,
		Parameters:  strings.TrimSpace(data.Params),
		Cancelled:   data.Cancelled,
		Executable:  data.Executable,
	}
	return item, nil
}

// getQueueItemDetails waits briefly for a queue item to receive an executable.
func (opts *JenkinsOptions) getQueueItemDetails(ctx context.Context, queueID int, maxWait time.Duration) (int, string) {
	deadline := time.Now().Add(maxWait)
	pollIntervals := []time.Duration{1 * time.Second, 2 * time.Second, 3 * time.Second, 5 * time.Second, 8 * time.Second, 11 * time.Second}

	for i := 0; ; i++ {
		item, err := opts.getQueueItem(ctx, queueID)
		if err == nil && item.Executable != nil && item.Executable.Number > 0 {
			return item.Executable.Number, item.Executable.URL
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		interval := min(pollIntervals[min(i, len(pollIntervals)-1)], remaining)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ""
		case <-timer.C:
		}
	}

	return 0, ""
}

// stopBuild stops a running Jenkins build.
func (opts *JenkinsOptions) stopBuild(ctx context.Context, jobName string, buildNumber int) (*StopBuildToolResponse, error) {
	jobPath := buildJobPath(jobName)
	apiPath := fmt.Sprintf("%s/%d/stop", jobPath, buildNumber)

	headers := map[string]string{}
	if f, c, ok, _ := opts.getCrumb(ctx); ok {
		headers[f] = c
	}

	resp, err := opts.callJenkins(ctx, opts.Client, http.MethodPost, apiPath, nil, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to stop build: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' build #%d not found", jobName, buildNumber)
	}
	// Jenkins returns 302 on successful stop
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return &StopBuildToolResponse{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Stopped:     true,
	}, nil
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

// buildAction represents a Jenkins build action (used to extract parameters).
type buildAction struct {
	Class      string `json:"_class"`
	Parameters []struct {
		Name  string `json:"name"`
		Value any    `json:"value"`
	} `json:"parameters"`
}

// extractBuildParams extracts build parameters from Jenkins actions.
func extractBuildParams(actions []buildAction) map[string]string {
	for _, a := range actions {
		if a.Class != "hudson.model.ParametersAction" || len(a.Parameters) == 0 {
			continue
		}
		params := make(map[string]string, len(a.Parameters))
		for _, p := range a.Parameters {
			params[p.Name] = fmt.Sprint(p.Value)
		}
		return params
	}
	return nil
}

// getJenkinsJob fetches a specific job from jenkins api by name
func (opts *JenkinsOptions) getJenkinsJob(ctx context.Context, jobName string, maxBuilds int) (*Job, error) {
	client := opts.Client

	// Build Jenkins job path for nested jobs/folders
	jobPath := buildJobPath(jobName)

	// Build the API URL for the specific job with expanded parameter information
	apiPath := jobPath + "/api/json?tree=" +
		"name,url,color,buildable,description," +
		"lastBuild[" +
		"number,url,building,result,timestamp,duration,estimatedDuration,displayName," +
		"actions[_class,parameters[name,value]]" +
		"]," +
		"builds[" +
		"number,url,building,result,timestamp,duration,estimatedDuration,displayName," +
		"actions[_class,parameters[name,value]]" +
		"]{0," + strconv.Itoa(maxBuilds) + "}," +
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
		Name        string `json:"name"`
		URL         string `json:"url"`
		Color       string `json:"color"`
		Buildable   bool   `json:"buildable"`
		Description string `json:"description"`
		LastBuild   *struct {
			Build
			Actions []buildAction `json:"actions"`
		} `json:"lastBuild"`
		Builds []struct {
			Build
			Actions []buildAction `json:"actions"`
		} `json:"builds"`
		Property []struct {
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
	for i, b := range jobData.Builds {
		recentBuilds[i] = b.Build
		recentBuilds[i].Parameters = extractBuildParams(b.Actions)
	}

	// Convert to our format
	var lastBuild *Build
	if jobData.LastBuild != nil {
		lb := jobData.LastBuild.Build
		lb.Parameters = extractBuildParams(jobData.LastBuild.Actions)
		lastBuild = &lb
	}
	jenkinsJob := &Job{
		Name:         jobData.Name,
		URL:          jobData.URL,
		Color:        jobData.Color,
		Buildable:    jobData.Buildable,
		Description:  jobData.Description,
		LastBuild:    lastBuild,
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

// searchBuilds fetches builds from Jenkins and filters by result and parameters.
func (opts *JenkinsOptions) searchBuilds(ctx context.Context, args SearchBuildsToolArgs) (*SearchBuildsToolResponse, error) {
	jobPath := buildJobPath(args.JobName)

	apiPath := jobPath + "/api/json?tree=" +
		"builds[" +
		"number,url,building,result,timestamp,duration,estimatedDuration,displayName," +
		"actions[_class,parameters[name,value]]" +
		"]{0," + strconv.Itoa(args.MaxLookback) + "}"

	resp, err := opts.callJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' not found", args.JobName)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, string(body))
	}

	var data struct {
		Builds []struct {
			Build
			Actions []buildAction `json:"actions"`
		} `json:"builds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse param filters
	type paramFilter struct {
		key   string
		value string
	}
	var filters []paramFilter
	for _, p := range args.Params {
		k, v, _ := strings.Cut(p, "=")
		filters = append(filters, paramFilter{k, v})
	}

	var matched []Build
	for _, b := range data.Builds {
		if args.Result != "" && b.Result != args.Result {
			continue
		}
		params := extractBuildParams(b.Actions)
		skip := false
		for _, f := range filters {
			got := params[f.key]
			if got != f.value {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		build := b.Build
		build.Parameters = params
		matched = append(matched, build)
		if len(matched) >= args.Limit {
			break
		}
	}

	return &SearchBuildsToolResponse{
		Builds:  matched,
		Scanned: len(data.Builds),
	}, nil
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

// getBuildDetails fetches detailed information about a specific build URL.
func (opts *JenkinsOptions) getBuildDetails(ctx context.Context, buildURL string) (*Build, error) {
	apiURL := strings.TrimRight(buildURL, "/") + "/api/json?tree=number,url,building,result,timestamp,duration,estimatedDuration,displayName,actions[_class,parameters[name,value]]"
	resp, err := opts.callJenkins(ctx, opts.Client, http.MethodGet, apiURL, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("build not found")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var buildData struct {
		Build
		Actions []buildAction `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&buildData); err != nil {
		return nil, err
	}
	build := buildData.Build
	build.Parameters = extractBuildParams(buildData.Actions)
	return &build, nil
}

// getBuildDetailsByJob fetches detailed information about a specific build by job path and build number.
func (opts *JenkinsOptions) getBuildDetailsByJob(ctx context.Context, jobName string, buildNumber int) (*Build, error) {
	jobPath := buildJobPath(jobName)
	apiPath := fmt.Sprintf("%s/%d/api/json?tree=number,url,building,result,timestamp,duration,estimatedDuration,displayName,actions[_class,parameters[name,value]]", jobPath, buildNumber)
	resp, err := opts.callJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' build #%d not found", jobName, buildNumber)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var buildData struct {
		Build
		Actions []buildAction `json:"actions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&buildData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	build := buildData.Build
	build.Parameters = extractBuildParams(buildData.Actions)
	return &build, nil
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

// waitForQueueItem waits for a Jenkins queue item to receive an executable, be cancelled, or timeout.
func (opts *JenkinsOptions) waitForQueueItem(ctx context.Context, queueID, timeoutSeconds, pollIntervalSeconds int) (*WaitForQueueItemToolResponse, error) {
	startTime := time.Now()
	timeout := time.Duration(timeoutSeconds) * time.Second
	pollInterval := time.Duration(pollIntervalSeconds) * time.Second
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		item, err := opts.getQueueItem(timeoutCtx, queueID)
		if err == nil {
			waitTime := time.Since(startTime)
			if item.Cancelled {
				return &WaitForQueueItemToolResponse{
					QueueItem: item,
					WaitTime:  DurationMS(waitTime),
					TimedOut:  false,
					Status:    "cancelled",
				}, nil
			}
			if item.Executable != nil && item.Executable.Number > 0 {
				return &WaitForQueueItemToolResponse{
					QueueItem: item,
					Build:     item.Executable,
					WaitTime:  DurationMS(waitTime),
					TimedOut:  false,
					Status:    "started",
				}, nil
			}
		}

		select {
		case <-timeoutCtx.Done():
			item, _ := opts.getQueueItem(ctx, queueID)
			return &WaitForQueueItemToolResponse{
				QueueItem: item,
				WaitTime:  DurationMS(time.Since(startTime)),
				TimedOut:  true,
				Status:    "timeout",
			}, nil
		case <-time.After(pollInterval):
		}
	}
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
	// Expected pattern is "jobName #buildNumber"; split on the last " #" so
	// job names that themselves contain " #" are handled.
	if i := strings.LastIndex(fullDisplayName, " #"); i >= 0 {
		if buildNumber, err := strconv.Atoi(fullDisplayName[i+2:]); err == nil {
			return fullDisplayName[:i], buildNumber
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
	mcp.AddTool(s, t, func(ctx context.Context, request *mcp.CallToolRequest, input In) (*mcp.CallToolResult, any, error) {
		return h(ctx, request, input)
	})
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
		showVer  bool
	)

	flag.StringVar(&opts.URL, "url", "", "Jenkins URL (required)")
	flag.StringVar(&opts.Auth, "auth", "", "Jenkins authentication in format 'user:api_token' (optional if JENKINS_MCP_AUTH env var is set)")
	flag.StringVar(&httpAddr, "http", "", "if set, use streamable HTTP at this address, instead of stdin/stdout")
	flag.BoolVar(&useStdio, "stdio", true, "use stdio transport (ignored if -http is set)")
	flag.BoolVar(&showVer, "version", false, "print version and exit")
	flag.Parse()

	if showVer {
		fmt.Println(getVersion())
		return
	}

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
	opts.User, opts.Token, _ = strings.Cut(opts.Auth, ":")
	opts.Client = &http.Client{Timeout: 30 * time.Second}
	opts.LogsClient = &http.Client{Timeout: 60 * time.Second}

	log.Printf("Using Jenkins URL: %s", opts.URL)
	log.Printf("Using Jenkins auth for user: %s", opts.User)

	// Build MCP server
	server := mcp.NewServer(&mcp.Implementation{Name: "jenkins-mcp-go", Version: getVersion()}, nil)

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
