package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	getJobsToolName             = "jenkins_get_jobs"
	getJobToolName              = "jenkins_get_job"
	getRunningBuildsToolName    = "jenkins_get_running_builds"
	getBuildLogsToolName        = "jenkins_get_build_logs"
	getBuildLogTailToolName     = "jenkins_get_build_log_tail"
	startJobToolName            = "jenkins_start_job"
	waitForRunningBuildToolName = "jenkins_wait_for_running_build"
)

// getJobsArgs are the tool arguments for get_jobs.
type getJobsArgs struct {
	// No arguments needed for the initial implementation
}

// getJobArgs are the tool arguments for get_job.
type getJobArgs struct {
	Name string `json:"name"`
}

// getRunningBuildsArgs are the tool arguments for get_running_builds.
type getRunningBuildsArgs struct {
	// No arguments needed for the initial implementation
}

// getBuildLogsArgs are the tool arguments for get_build_logs.
type getBuildLogsArgs struct {
	Name        string `json:"name"`
	BuildNumber int    `json:"build_number"`
	Offset      int    `json:"offset,omitempty"`
	Length      int    `json:"length,omitempty"`
}

// getBuildLogTailArgs are the tool arguments for get_build_log_tail.
type getBuildLogTailArgs struct {
	JobName     string `json:"job_name"`
	BuildNumber int    `json:"build_number"`
	MaxLength   int    `json:"max_length,omitempty"`
}

// startJobArgs are the tool arguments for start_job.
type startJobArgs struct {
	JobName    string                 `json:"job_name"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	// wait: "none" (default), "queued", or "started"
	Wait string `json:"wait,omitempty"`
}

// waitForRunningBuildArgs are the tool arguments for wait_for_running_build.
type waitForRunningBuildArgs struct {
	JobName        string `json:"job_name"`
	BuildNumber    int    `json:"build_number"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// StartJobResponse represents the response from start_job
type StartJobResponse struct {
	JobName     string `json:"jobName"`
	QueueURL    string `json:"queueUrl,omitempty"`
	BuildURL    string `json:"buildUrl,omitempty"`
	BuildNumber int    `json:"buildNumber,omitempty"`
}

// WaitForRunningBuildResponse represents the response from wait_for_running_build
type WaitForRunningBuildResponse struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	Status      string `json:"status"`   // "success", "failure", "unstable", "aborted", "timeout"
	Result      string `json:"result"`   // Jenkins result string (SUCCESS, FAILURE, UNSTABLE, ABORTED, or empty if timeout)
	Duration    int64  `json:"duration"` // Total build duration in milliseconds
	WaitTime    int64  `json:"waitTime"` // Time spent waiting in milliseconds
	TimedOut    bool   `json:"timedOut"` // Whether the wait operation timed out
}

// BuildLogsResponse represents the response from get_build_logs
type BuildLogsResponse struct {
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
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	URL         string `json:"url"`
	StartTime   int64  `json:"startTime"` // Unix timestamp in milliseconds
	Duration    int64  `json:"duration"`  // Current duration in milliseconds
	Executor    string `json:"executor"`  // Executor information
	Progress    int    `json:"progress"`  // Progress percentage (if available)
}

// JenkinsOptions bundles configuration for Jenkins API calls.
type JenkinsOptions struct {
	URL        string
	Auth       string // format: "user:api_token" (kept for backward compatibility)
	User       string
	Token      string
	Client     *http.Client
	LogsClient *http.Client
}

// JenkinsJob represents a Jenkins job with its current status
type JenkinsJob struct {
	Name        string           `json:"name"`
	URL         string           `json:"url"`
	Color       string           `json:"color"`       // Jenkins color coding (blue, red, yellow, etc.)
	Buildable   bool             `json:"buildable"`   // Whether the job can be built
	Description string           `json:"description"` // Job description
	LastBuild   *Build           `json:"lastBuild"`   // Most recent build info
	Parameters  []BuildParameter `json:"parameters"`  // Build parameters
}

// BuildParameter represents a Jenkins build parameter
type BuildParameter struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Description  string      `json:"description"`
	DefaultValue interface{} `json:"defaultValue"`
	Choices      []string    `json:"choices,omitempty"` // For choice parameters
}

// Build represents a Jenkins build
type Build struct {
	Number    int    `json:"number"`
	URL       string `json:"url"`
	Building  bool   `json:"building"`
	Result    string `json:"result"`    // SUCCESS, FAILURE, UNSTABLE, ABORTED, null if building
	Timestamp int64  `json:"timestamp"` // Unix timestamp in milliseconds
	Duration  int64  `json:"duration"`  // Duration in milliseconds
}

// JenkinsAPIResponse represents the response from Jenkins /api/json
type JenkinsAPIResponse struct {
	Jobs []struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		Color       string `json:"color"`
		Buildable   bool   `json:"buildable"`
		Description string `json:"description"`
		LastBuild   *struct {
			Number int    `json:"number"`
			URL    string `json:"url"`
		} `json:"lastBuild"`
	} `json:"jobs"`
}

func main() {
	// Prepare options and bind flags directly to fields.
	opts := &JenkinsOptions{}
	var (
		httpAddr string
		useStdio bool
	)

	flag.StringVar(&opts.URL, "url", "", "Jenkins URL (required)")
	flag.StringVar(&opts.Auth, "auth", "", "Jenkins authentication in format 'user:api_token' (required)")
	flag.StringVar(&httpAddr, "http", "", "if set, use streamable HTTP at this address, instead of stdin/stdout")
	flag.BoolVar(&useStdio, "stdio", true, "use stdio transport (ignored if -http is set)")
	flag.Parse()

	// Validate required parameters
	if opts.URL == "" {
		fmt.Fprintln(os.Stderr, "Error: -url parameter is required")
		os.Exit(1)
	}
	if opts.Auth == "" {
		fmt.Fprintln(os.Stderr, "Error: -auth parameter is required")
		os.Exit(1)
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

	// Build input schema for get_jobs tool
	getJobsInputSchema, err := jsonschema.For[getJobsArgs](nil)
	if err != nil {
		log.Fatalf("build get_jobs input schema: %v", err)
	}

	mcp.AddTool[getJobsArgs, any](server, &mcp.Tool{
		Name:        getJobsToolName,
		Description: "Get list of Jenkins jobs with their current status",
		InputSchema: getJobsInputSchema,
	}, func(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[getJobsArgs]]) (*mcp.CallToolResultFor[any], error) {
		// Fetch jobs from Jenkins API
		jobs, err := getJenkinsJobs(ctx, opts)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
				IsError: true,
			}, nil
		}

		// Convert jobs to JSON string for response
		jobsJSON, err := json.Marshal(jobs)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error marshaling jobs: %v", err)}},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: string(jobsJSON)}},
		}, nil
	})

	// Build input schema for get_job tool
	getJobInputSchema, err := jsonschema.For[getJobArgs](nil)
	if err != nil {
		log.Fatalf("build get_job input schema: %v", err)
	}
	if getJobInputSchema.Properties == nil {
		getJobInputSchema.Properties = make(map[string]*jsonschema.Schema)
	}
	if p, ok := getJobInputSchema.Properties["name"]; ok && p != nil {
		p.Description = "Name of the Jenkins job to retrieve"
	}

	mcp.AddTool[getJobArgs, any](server, &mcp.Tool{
		Name:        getJobToolName,
		Description: "Get detailed information about a specific Jenkins job by name",
		InputSchema: getJobInputSchema,
	}, func(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[getJobArgs]]) (*mcp.CallToolResultFor[any], error) {
		args := req.Params.Arguments
		if strings.TrimSpace(args.Name) == "" {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: "Missing required argument: name"}},
				IsError: true,
			}, nil
		}

		// Fetch specific job from Jenkins API
		job, err := getJenkinsJob(ctx, opts, args.Name)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
				IsError: true,
			}, nil
		}

		// Convert job to JSON string for response
		jobJSON, err := json.Marshal(job)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error marshaling job: %v", err)}},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: string(jobJSON)}},
		}, nil
	})

	// Build input schema for get_running_builds tool
	getRunningBuildsInputSchema, err := jsonschema.For[getRunningBuildsArgs](nil)
	if err != nil {
		log.Fatalf("build get_running_builds input schema: %v", err)
	}

	mcp.AddTool[getRunningBuildsArgs, any](server, &mcp.Tool{
		Name:        getRunningBuildsToolName,
		Description: "Get list of currently running Jenkins builds",
		InputSchema: getRunningBuildsInputSchema,
	}, func(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[getRunningBuildsArgs]]) (*mcp.CallToolResultFor[any], error) {
		// Fetch running builds from Jenkins API
		runningBuilds, err := getRunningBuilds(ctx, opts)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
				IsError: true,
			}, nil
		}

		// Convert running builds to JSON string for response
		buildsJSON, err := json.Marshal(runningBuilds)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error marshaling running builds: %v", err)}},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: string(buildsJSON)}},
		}, nil
	})

	// Build input schema for get_build_logs tool
	getBuildLogsInputSchema, err := jsonschema.For[getBuildLogsArgs](nil)
	if err != nil {
		log.Fatalf("build get_build_logs input schema: %v", err)
	}
	if getBuildLogsInputSchema.Properties == nil {
		getBuildLogsInputSchema.Properties = make(map[string]*jsonschema.Schema)
	}
	if p, ok := getBuildLogsInputSchema.Properties["name"]; ok && p != nil {
		p.Description = "Name of the Jenkins job"
	}
	if p, ok := getBuildLogsInputSchema.Properties["build_number"]; ok && p != nil {
		p.Description = "Build number to get logs for"
	}
	if p, ok := getBuildLogsInputSchema.Properties["offset"]; ok && p != nil {
		p.Description = "Starting byte offset in the log file (default: 0)"
		p.Default = json.RawMessage("0")
	}
	if p, ok := getBuildLogsInputSchema.Properties["length"]; ok && p != nil {
		p.Description = "Maximum number of bytes to retrieve (default: 8192)"
		p.Default = json.RawMessage("8192")
	}

	mcp.AddTool[getBuildLogsArgs, any](server, &mcp.Tool{
		Name:        getBuildLogsToolName,
		Description: "Get build logs for a specific Jenkins job and build number with pagination support",
		InputSchema: getBuildLogsInputSchema,
	}, func(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[getBuildLogsArgs]]) (*mcp.CallToolResultFor[any], error) {
		args := req.Params.Arguments
		if strings.TrimSpace(args.Name) == "" {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: "Missing required argument: name"}},
				IsError: true,
			}, nil
		}
		if args.BuildNumber <= 0 {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: "Missing or invalid required argument: build_number (must be > 0)"}},
				IsError: true,
			}, nil
		}

		// Set defaults
		if args.Length <= 0 {
			args.Length = 8192
		}
		if args.Offset < 0 {
			args.Offset = 0
		}

		// Fetch build logs from Jenkins API
		logsResponse, err := getBuildLogs(ctx, opts, args.Name, args.BuildNumber, args.Offset, args.Length)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
				IsError: true,
			}, nil
		}

		// Convert logs response to JSON string for response
		logsJSON, err := json.Marshal(logsResponse)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error marshaling logs response: %v", err)}},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: string(logsJSON)}},
		}, nil
	})

	// Build input schema for get_build_log_tail tool
	getBuildLogTailInputSchema, err := jsonschema.For[getBuildLogTailArgs](nil)
	if err != nil {
		log.Fatalf("build get_build_log_tail input schema: %v", err)
	}
	if getBuildLogTailInputSchema.Properties == nil {
		getBuildLogTailInputSchema.Properties = make(map[string]*jsonschema.Schema)
	}
	if p, ok := getBuildLogTailInputSchema.Properties["job_name"]; ok && p != nil {
		p.Description = "Name of the Jenkins job"
	}
	if p, ok := getBuildLogTailInputSchema.Properties["build_number"]; ok && p != nil {
		p.Description = "Build number to get logs for"
	}
	if p, ok := getBuildLogTailInputSchema.Properties["max_length"]; ok && p != nil {
		p.Description = "Maximum number of bytes to retrieve from the end of the log (default: 8192)"
		p.Default = json.RawMessage("8192")
	}

	mcp.AddTool[getBuildLogTailArgs, any](server, &mcp.Tool{
		Name:        getBuildLogTailToolName,
		Description: "Get the tail of build logs for a specific Jenkins job and build number - useful for seeing why builds failed",
		InputSchema: getBuildLogTailInputSchema,
	}, func(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[getBuildLogTailArgs]]) (*mcp.CallToolResultFor[any], error) {
		args := req.Params.Arguments
		if strings.TrimSpace(args.JobName) == "" {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: "Missing required argument: job_name"}},
				IsError: true,
			}, nil
		}
		if args.BuildNumber <= 0 {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: "Missing or invalid required argument: build_number (must be > 0)"}},
				IsError: true,
			}, nil
		}

		// Set default
		if args.MaxLength <= 0 {
			args.MaxLength = 8192
		}

		// Fetch build log tail from Jenkins API
		logsResponse, err := getBuildLogTail(ctx, opts, args.JobName, args.BuildNumber, args.MaxLength)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
				IsError: true,
			}, nil
		}

		// Convert logs response to JSON string for response
		logsJSON, err := json.Marshal(logsResponse)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Error marshaling logs response: %v", err)}},
				IsError: true,
			}, nil
		}

		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: string(logsJSON)}},
		}, nil
	})

	// Build input schema for start_job tool
	startJobInputSchema, err := jsonschema.For[startJobArgs](nil)
	if err != nil {
		log.Fatalf("build start_job input schema: %v", err)
	}
	if startJobInputSchema.Properties == nil {
		startJobInputSchema.Properties = make(map[string]*jsonschema.Schema)
	}
	if p, ok := startJobInputSchema.Properties["job_name"]; ok && p != nil {
		p.Description = "Name/path of the Jenkins job (supports folders)"
	}
	if p, ok := startJobInputSchema.Properties["parameters"]; ok && p != nil {
		p.Description = "Build parameters as a key/value object"
	}
	if p, ok := startJobInputSchema.Properties["wait"]; ok && p != nil {
		p.Description = "When to return: 'none' (default), 'queued', or 'started'"
	}

	mcp.AddTool[startJobArgs, any](server, &mcp.Tool{
		Name:        startJobToolName,
		Description: "Trigger a Jenkins job build with optional parameters and wait behavior",
		InputSchema: startJobInputSchema,
	}, func(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[startJobArgs]]) (*mcp.CallToolResultFor[any], error) {
		args := req.Params.Arguments
		if strings.TrimSpace(args.JobName) == "" {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: "Missing required argument: job_name"}},
				IsError: true,
			}, nil
		}
		if args.Wait == "" {
			args.Wait = "none"
		}
		switch args.Wait {
		case "none", "queued", "started":
		default:
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: "Invalid wait value: expected 'none', 'queued', or 'started'"}},
				IsError: true,
			}, nil
		}

		res, err := startJob(ctx, opts, args.JobName, args.Parameters, args.Wait)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
				IsError: true,
			}, nil
		}

		b, _ := json.Marshal(res)
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
		}, nil
	})

	// Build input schema for wait_for_running_build tool
	waitForRunningBuildInputSchema, err := jsonschema.For[waitForRunningBuildArgs](nil)
	if err != nil {
		log.Fatalf("build wait_for_running_build input schema: %v", err)
	}
	if waitForRunningBuildInputSchema.Properties == nil {
		waitForRunningBuildInputSchema.Properties = make(map[string]*jsonschema.Schema)
	}
	if p, ok := waitForRunningBuildInputSchema.Properties["job_name"]; ok && p != nil {
		p.Description = "Name of the Jenkins job"
	}
	if p, ok := waitForRunningBuildInputSchema.Properties["build_number"]; ok && p != nil {
		p.Description = "Build number to wait for"
	}
	if p, ok := waitForRunningBuildInputSchema.Properties["timeout_seconds"]; ok && p != nil {
		p.Description = "Maximum time to wait in seconds (default: 600)"
	}

	mcp.AddTool[waitForRunningBuildArgs, any](server, &mcp.Tool{
		Name:        waitForRunningBuildToolName,
		Description: "Wait for a running Jenkins build to complete or timeout",
		InputSchema: waitForRunningBuildInputSchema,
	}, func(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[waitForRunningBuildArgs]]) (*mcp.CallToolResultFor[any], error) {
		args := req.Params.Arguments
		if strings.TrimSpace(args.JobName) == "" {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: "Missing required argument: job_name"}},
				IsError: true,
			}, nil
		}
		if args.BuildNumber <= 0 {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: "Missing or invalid required argument: build_number"}},
				IsError: true,
			}, nil
		}
		if args.TimeoutSeconds <= 0 {
			args.TimeoutSeconds = 600 // Default 10 minutes
		}

		res, err := waitForRunningBuild(ctx, opts, args.JobName, args.BuildNumber, args.TimeoutSeconds)
		if err != nil {
			return &mcp.CallToolResultFor[any]{
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
				IsError: true,
			}, nil
		}

		b, _ := json.Marshal(res)
		return &mcp.CallToolResultFor[any]{
			Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
		}, nil
	})

	// Choose transport
	if httpAddr != "" {
		handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server { return server }, nil)
		log.Printf("Starting MCP HTTP server on %s", httpAddr)
		if err := http.ListenAndServe(httpAddr, handler); err != nil {
			log.Fatalf("http server error: %v", err)
		}
	} else if useStdio {
		log.Printf("Starting MCP server over stdio")
		if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("server error: %v", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: no transport selected. Use -http or -stdio.")
		os.Exit(1)
	}
}

// buildJobPath builds a Jenkins job path supporting nested folders.
// Example: "folder1/folder2/jobName" -> "/job/folder1/job/folder2/job/jobName"
func buildJobPath(jobName string) string {
	segs := strings.Split(jobName, "/")
	var b strings.Builder
	for i, s := range segs {
		if s == "" {
			continue
		}
		if i > 0 {
			b.WriteString("/job/")
		} else {
			b.WriteString("/job/")
		}
		b.WriteString(url.PathEscape(s))
	}
	return b.String()
}

// getCrumb fetches Jenkins CSRF crumb and header field name.
func getCrumb(ctx context.Context, opts *JenkinsOptions) (field, crumb string, ok bool, err error) {
	apiURL := strings.TrimRight(opts.URL, "/") + "/crumbIssuer/api/json"
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return "", "", false, err
	}
	req.SetBasicAuth(opts.User, opts.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.Client.Do(req)
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
func startJob(ctx context.Context, opts *JenkinsOptions, jobName string, params map[string]interface{}, wait string) (*StartJobResponse, error) {
	jobPath := buildJobPath(jobName)
	base := strings.TrimRight(opts.URL, "/")

	// Always use buildWithParameters endpoint as it works for both parameterized and non-parameterized jobs
	endpoint := base + jobPath + "/buildWithParameters"

	form := url.Values{}
	for k, v := range params {
		form.Set(k, fmt.Sprint(v))
	}
	// If no parameters provided, still send the form (empty is fine for buildWithParameters)

	body := strings.NewReader(form.Encode())

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create build request: %w", err)
	}
	req.SetBasicAuth(opts.User, opts.Token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if f, c, ok, _ := getCrumb(ctx, opts); ok {
		req.Header.Set(f, c)
	}

	resp, err := opts.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to start build: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Jenkins returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Capture queue URL from Location header if present
	queueURL := resp.Header.Get("Location")
	result := &StartJobResponse{JobName: jobName}
	if queueURL != "" {
		result.QueueURL = queueURL
	}

	switch wait {
	case "none":
		return result, nil
	case "queued":
		// We already have queue URL (if provided). Return now.
		return result, nil
	case "started":
		if queueURL == "" {
			return result, nil // cannot wait without queue URL
		}
		// Poll queue item until executable is assigned
		// Use a reasonable default timeout
		waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-waitCtx.Done():
				return result, nil
			case <-ticker.C:
				qreq, err := http.NewRequestWithContext(waitCtx, "GET", strings.TrimRight(queueURL, "/")+"/api/json", nil)
				if err != nil {
					return result, nil
				}
				qreq.SetBasicAuth(opts.User, opts.Token)
				qreq.Header.Set("Accept", "application/json")
				qresp, err := opts.Client.Do(qreq)
				if err != nil {
					continue
				}
				func() {
					defer qresp.Body.Close()
					if qresp.StatusCode != http.StatusOK {
						return
					}
					var q struct {
						Cancelled  bool `json:"cancelled"`
						Executable *struct {
							Number int    `json:"number"`
							URL    string `json:"url"`
						} `json:"executable"`
					}
					if err := json.NewDecoder(qresp.Body).Decode(&q); err != nil {
						return
					}
					if q.Cancelled {
						// leave result without build info
						return
					}
					if q.Executable != nil {
						result.BuildNumber = q.Executable.Number
						result.BuildURL = q.Executable.URL
						// done
						cancel()
					}
				}()
			}
			if waitCtx.Err() != nil {
				return result, nil
			}
			if result.BuildNumber > 0 || result.BuildURL != "" {
				return result, nil
			}
		}
	default:
		return result, nil
	}
}

// getBuildLogTail fetches the tail of build logs from Jenkins API
func getBuildLogTail(ctx context.Context, opts *JenkinsOptions, jobName string, buildNumber, maxLength int) (*BuildLogsResponse, error) {
	client := opts.LogsClient

	// First, get the total log size to calculate the offset for the tail
	// Build Jenkins job path for nested jobs/folders
	jobPath := buildJobPath(jobName)

	// Get log size using progressiveText API
	sizeURL := fmt.Sprintf("%s%s/%d/logText/progressiveText?start=0",
		strings.TrimRight(opts.URL, "/"), jobPath, buildNumber)

	// Create request to get log size
	req, err := http.NewRequestWithContext(ctx, "GET", sizeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create size request: %w", err)
	}

	// Add basic auth header
	req.SetBasicAuth(opts.User, opts.Token)
	req.Header.Set("Accept", "text/plain")

	// Make the request to get size
	resp, err := client.Do(req)
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
		return nil, fmt.Errorf("Jenkins API returned status %d: %s", resp.StatusCode, string(body))
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
			return &BuildLogsResponse{
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

	// Calculate offset for the tail
	offset := totalSize - maxLength
	if offset < 0 {
		offset = 0
		maxLength = totalSize
	}

	// Now get the actual tail logs
	tailURL := fmt.Sprintf("%s%s/%d/logText/progressiveText?start=%d",
		strings.TrimRight(opts.URL, "/"), jobPath, buildNumber, offset)

	// Create request for tail logs
	tailReq, err := http.NewRequestWithContext(ctx, "GET", tailURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create tail request: %w", err)
	}

	tailReq.SetBasicAuth(opts.User, opts.Token)
	tailReq.Header.Set("Accept", "text/plain")

	// Make the request for tail logs
	tailResp, err := client.Do(tailReq)
	if err != nil {
		return nil, fmt.Errorf("failed to make tail request: %w", err)
	}
	defer tailResp.Body.Close()

	if tailResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tailResp.Body)
		return nil, fmt.Errorf("Jenkins API returned status %d: %s", tailResp.StatusCode, string(body))
	}

	// Read the tail logs
	logData, err := io.ReadAll(tailResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read tail response body: %w", err)
	}

	logs := string(logData)

	// Limit the response to the requested length (in case we got more)
	if len(logs) > maxLength {
		logs = logs[len(logs)-maxLength:]
		offset = totalSize - len(logs)
	}

	// Check if the build is still running
	hasMore := tailResp.Header.Get("X-More-Data") == "true"

	return &BuildLogsResponse{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Offset:      offset,
		Length:      len(logs),
		TotalSize:   totalSize,
		HasMore:     hasMore,
		Logs:        logs,
	}, nil
}

// getBuildLogs fetches build logs from Jenkins API with pagination support
func getBuildLogs(ctx context.Context, opts *JenkinsOptions, jobName string, buildNumber, offset, length int) (*BuildLogsResponse, error) {
	client := opts.LogsClient

	// Build Jenkins job path for nested jobs/folders
	jobPath := buildJobPath(jobName)

	// Build the API URL for build logs with range parameters
	// Jenkins supports HTTP Range headers for log pagination
	apiURL := fmt.Sprintf("%s%s/%d/logText/progressiveText?start=%d",
		strings.TrimRight(opts.URL, "/"), jobPath, buildNumber, offset)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add basic auth header
	req.SetBasicAuth(opts.User, opts.Token)
	req.Header.Set("Accept", "text/plain")

	// Make the request
	resp, err := client.Do(req)
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
		return nil, fmt.Errorf("Jenkins API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read the response body
	logData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Limit the response to the requested length
	logs := string(logData)
	if len(logs) > length {
		logs = logs[:length]
	}

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

	return &BuildLogsResponse{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Offset:      offset,
		Length:      len(logs),
		TotalSize:   totalSize,
		HasMore:     hasMore,
		Logs:        logs,
	}, nil
}

// getJenkinsJob fetches a specific job from Jenkins API by name
func getJenkinsJob(ctx context.Context, opts *JenkinsOptions, jobName string) (*JenkinsJob, error) {
	client := opts.Client

	// Build Jenkins job path for nested jobs/folders
	jobPath := buildJobPath(jobName)

	// Build the API URL for the specific job with expanded parameter information
	apiURL := strings.TrimRight(opts.URL, "/") + jobPath + "/api/json?tree=name,url,color,buildable,description,lastBuild[number,url],property[parameterDefinitions[name,type,description,defaultParameterValue[value],choices]]"

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add basic auth header
	req.SetBasicAuth(opts.User, opts.Token)
	req.Header.Set("Accept", "application/json")

	// Make the request
	resp, err := client.Do(req)
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
		return nil, fmt.Errorf("Jenkins API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var jobData struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		Color       string `json:"color"`
		Buildable   bool   `json:"buildable"`
		Description string `json:"description"`
		LastBuild   *struct {
			Number int    `json:"number"`
			URL    string `json:"url"`
		} `json:"lastBuild"`
		Property []struct {
			ParameterDefinitions []struct {
				Name                  string `json:"name"`
				Type                  string `json:"type"`
				Description           string `json:"description"`
				DefaultParameterValue *struct {
					Value interface{} `json:"value"`
				} `json:"defaultParameterValue"`
				Choices []string `json:"choices"`
			} `json:"parameterDefinitions"`
		} `json:"property"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jobData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to our format
	jenkinsJob := &JenkinsJob{
		Name:        jobData.Name,
		URL:         jobData.URL,
		Color:       jobData.Color,
		Buildable:   jobData.Buildable,
		Description: jobData.Description,
		Parameters:  []BuildParameter{},
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

	// If there's a last build, fetch its details
	if jobData.LastBuild != nil {
		build, err := getBuildDetails(ctx, opts, jobData.LastBuild.URL)
		if err != nil {
			log.Printf("Warning: failed to get build details for %s: %v", jobData.Name, err)
			// Still include the job but without detailed build info
			jenkinsJob.LastBuild = &Build{
				Number: jobData.LastBuild.Number,
				URL:    jobData.LastBuild.URL,
			}
		} else {
			jenkinsJob.LastBuild = build
		}
	}

	return jenkinsJob, nil
}

// getJenkinsJobs fetches jobs from Jenkins API
func getJenkinsJobs(ctx context.Context, opts *JenkinsOptions) ([]JenkinsJob, error) {
	client := opts.Client

	// Build the API URL
	apiURL := strings.TrimRight(opts.URL, "/") + "/api/json?tree=jobs[name,url,color,buildable,description,lastBuild[number,url]]"

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add basic auth header
	req.SetBasicAuth(opts.User, opts.Token)
	req.Header.Set("Accept", "application/json")

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Jenkins API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp JenkinsAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to our format
	jobs := make([]JenkinsJob, len(apiResp.Jobs))
	type workItem struct {
		idx  int
		url  string
		name string
	}
	var work []workItem

	for i, job := range apiResp.Jobs {
		jobs[i] = JenkinsJob{
			Name:        job.Name,
			URL:         job.URL,
			Color:       job.Color,
			Buildable:   job.Buildable,
			Description: job.Description,
		}
		if job.LastBuild != nil {
			jobs[i].LastBuild = &Build{Number: job.LastBuild.Number, URL: job.LastBuild.URL}
			work = append(work, workItem{idx: i, url: job.LastBuild.URL, name: job.Name})
		}
	}

	if len(work) > 0 {
		workers := 6
		if len(work) < workers {
			workers = len(work)
		}
		ch := make(chan workItem)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for it := range ch {
					build, err := getBuildDetails(ctx, opts, it.url)
					if err != nil {
						log.Printf("Warning: failed to get build details for %s: %v", it.name, err)
						continue
					}
					jobs[it.idx].LastBuild = build
				}
			}()
		}
		for _, it := range work {
			ch <- it
		}
		close(ch)
		wg.Wait()
	}

	return jobs, nil
}

// getBuildDetails fetches detailed information about a specific build
func getBuildDetails(ctx context.Context, opts *JenkinsOptions, buildURL string) (*Build, error) {
	// Add /api/json to the build URL if not already present
	apiURL := strings.TrimRight(buildURL, "/") + "/api/json"

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	// Add basic auth header
	req.SetBasicAuth(opts.User, opts.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	var buildData struct {
		Number    int    `json:"number"`
		URL       string `json:"url"`
		Building  bool   `json:"building"`
		Result    string `json:"result"`
		Timestamp int64  `json:"timestamp"`
		Duration  int64  `json:"duration"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&buildData); err != nil {
		return nil, err
	}

	return &Build{
		Number:    buildData.Number,
		URL:       buildData.URL,
		Building:  buildData.Building,
		Result:    buildData.Result,
		Timestamp: buildData.Timestamp,
		Duration:  buildData.Duration,
	}, nil
}

// getRunningBuilds fetches currently running builds from Jenkins API
func getRunningBuilds(ctx context.Context, opts *JenkinsOptions) ([]RunningBuild, error) {
	client := opts.Client

	// Build the API URL for computer information (includes executors)
	apiURL := strings.TrimRight(opts.URL, "/") + "/computer/api/json?tree=computer[displayName,executors[currentExecutable[url,fullDisplayName,timestamp],idle,likelyStuck,progress]]"

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add basic auth header
	req.SetBasicAuth(opts.User, opts.Token)
	req.Header.Set("Accept", "application/json")

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Jenkins API returned status %d: %s", resp.StatusCode, string(body))
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
				Progress    int  `json:"progress"`
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

			runningBuild := RunningBuild{
				JobName:     jobName,
				BuildNumber: buildNumber,
				URL:         executable.URL,
				StartTime:   executable.Timestamp,
				Duration:    currentTime - executable.Timestamp,
				Executor:    computer.DisplayName,
				Progress:    executor.Progress,
			}

			runningBuilds = append(runningBuilds, runningBuild)
		}
	}

	return runningBuilds, nil
}

// waitForRunningBuild waits for a Jenkins build to complete or timeout
func waitForRunningBuild(ctx context.Context, opts *JenkinsOptions, jobName string, buildNumber, timeoutSeconds int) (*WaitForRunningBuildResponse, error) {
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
			waitTime := time.Since(startTime).Milliseconds()
			return &WaitForRunningBuildResponse{
				JobName:     jobName,
				BuildNumber: buildNumber,
				Status:      "timeout",
				Result:      "",
				Duration:    0,
				WaitTime:    waitTime,
				TimedOut:    true,
			}, nil

		case <-ticker.C:
			// Poll the build status
			build, err := getBuildDetails(ctx, opts, buildURL)
			if err != nil {
				// If we can't get build details, continue polling
				// This might happen if the build hasn't started yet
				continue
			}

			// Check if build is complete
			if !build.Building {
				waitTime := time.Since(startTime).Milliseconds()

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

				return &WaitForRunningBuildResponse{
					JobName:     jobName,
					BuildNumber: buildNumber,
					Status:      status,
					Result:      build.Result,
					Duration:    build.Duration,
					WaitTime:    waitTime,
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
