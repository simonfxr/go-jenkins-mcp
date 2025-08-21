package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	getJobsToolName            = "get_jobs"
	getJobToolName             = "get_job"
	getRunningBuildsToolName   = "get_running_builds"
	getBuildLogsToolName       = "get_build_logs"
	getBuildLogsSuffixToolName = "get_build_logs_suffix"
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

// getBuildLogsSuffixArgs are the tool arguments for get_build_logs_suffix.
type getBuildLogsSuffixArgs struct {
	JobName     string `json:"job_name"`
	BuildNumber int    `json:"build_number"`
	MaxLength   int    `json:"max_length,omitempty"`
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
	URL  string
	Auth string // format: "user:api_token"
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
	flag.BoolVar(&useStdio, "stdio", true, "use stdio transport")
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
	getJobInputSchema.Properties["name"].Description = "Name of the Jenkins job to retrieve"

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
	getBuildLogsInputSchema.Properties["name"].Description = "Name of the Jenkins job"
	getBuildLogsInputSchema.Properties["build_number"].Description = "Build number to get logs for"
	getBuildLogsInputSchema.Properties["offset"].Description = "Starting byte offset in the log file (default: 0)"
	getBuildLogsInputSchema.Properties["offset"].Default = json.RawMessage("0")
	getBuildLogsInputSchema.Properties["length"].Description = "Maximum number of bytes to retrieve (default: 8192)"
	getBuildLogsInputSchema.Properties["length"].Default = json.RawMessage("8192")

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

	// Build input schema for get_build_logs_suffix tool
	getBuildLogsSuffixInputSchema, err := jsonschema.For[getBuildLogsSuffixArgs](nil)
	if err != nil {
		log.Fatalf("build get_build_logs_suffix input schema: %v", err)
	}
	if getBuildLogsSuffixInputSchema.Properties == nil {
		getBuildLogsSuffixInputSchema.Properties = make(map[string]*jsonschema.Schema)
	}
	getBuildLogsSuffixInputSchema.Properties["job_name"].Description = "Name of the Jenkins job"
	getBuildLogsSuffixInputSchema.Properties["build_number"].Description = "Build number to get logs for"
	getBuildLogsSuffixInputSchema.Properties["max_length"].Description = "Maximum number of bytes to retrieve from the end of the log (default: 8192)"
	getBuildLogsSuffixInputSchema.Properties["max_length"].Default = json.RawMessage("8192")

	mcp.AddTool[getBuildLogsSuffixArgs, any](server, &mcp.Tool{
		Name:        getBuildLogsSuffixToolName,
		Description: "Get the tail/suffix of build logs for a specific Jenkins job and build number - useful for seeing why builds failed",
		InputSchema: getBuildLogsSuffixInputSchema,
	}, func(ctx context.Context, req *mcp.ServerRequest[*mcp.CallToolParamsFor[getBuildLogsSuffixArgs]]) (*mcp.CallToolResultFor[any], error) {
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

		// Fetch build logs suffix from Jenkins API
		logsResponse, err := getBuildLogsSuffix(ctx, opts, args.JobName, args.BuildNumber, args.MaxLength)
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

	// Choose transport
	if httpAddr != "" {
		handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server { return server }, nil)
		log.Printf("Starting MCP HTTP server on %s", httpAddr)
		if err := http.ListenAndServe(httpAddr, handler); err != nil {
			log.Fatalf("http server error: %v", err)
		}
	} else {
		if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("server error: %v", err)
		}
	}
}

// getBuildLogsSuffix fetches the tail/suffix of build logs from Jenkins API
func getBuildLogsSuffix(ctx context.Context, opts *JenkinsOptions, jobName string, buildNumber, maxLength int) (*BuildLogsResponse, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 60 * time.Second, // Longer timeout for log retrieval
	}

	// First, get the total log size to calculate the offset for the tail
	// URL encode the job name to handle special characters and spaces
	encodedJobName := strings.ReplaceAll(jobName, "/", "%2F")

	// Get log size using progressiveText API
	sizeURL := fmt.Sprintf("%s/job/%s/%d/logText/progressiveText?start=0",
		strings.TrimRight(opts.URL, "/"), encodedJobName, buildNumber)

	// Create request to get log size
	req, err := http.NewRequestWithContext(ctx, "GET", sizeURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create size request: %w", err)
	}

	// Add basic auth header
	auth := base64.StdEncoding.EncodeToString([]byte(opts.Auth))
	req.Header.Set("Authorization", "Basic "+auth)
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
	tailURL := fmt.Sprintf("%s/job/%s/%d/logText/progressiveText?start=%d",
		strings.TrimRight(opts.URL, "/"), encodedJobName, buildNumber, offset)

	// Create request for tail logs
	tailReq, err := http.NewRequestWithContext(ctx, "GET", tailURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create tail request: %w", err)
	}

	tailReq.Header.Set("Authorization", "Basic "+auth)
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
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 60 * time.Second, // Longer timeout for log retrieval
	}

	// URL encode the job name to handle special characters and spaces
	encodedJobName := strings.ReplaceAll(jobName, "/", "%2F")

	// Build the API URL for build logs with range parameters
	// Jenkins supports HTTP Range headers for log pagination
	apiURL := fmt.Sprintf("%s/job/%s/%d/logText/progressiveText?start=%d",
		strings.TrimRight(opts.URL, "/"), encodedJobName, buildNumber, offset)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add basic auth header
	auth := base64.StdEncoding.EncodeToString([]byte(opts.Auth))
	req.Header.Set("Authorization", "Basic "+auth)
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
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// URL encode the job name to handle special characters and spaces
	encodedJobName := strings.ReplaceAll(jobName, "/", "%2F")

	// Build the API URL for the specific job with expanded parameter information
	apiURL := strings.TrimRight(opts.URL, "/") + "/job/" + encodedJobName + "/api/json?tree=name,url,color,buildable,description,lastBuild[number,url],property[parameterDefinitions[name,type,description,defaultParameterValue[value],choices]]"

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add basic auth header
	auth := base64.StdEncoding.EncodeToString([]byte(opts.Auth))
	req.Header.Set("Authorization", "Basic "+auth)
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
		build, err := getBuildDetails(ctx, client, opts.Auth, jobData.LastBuild.URL)
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
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Build the API URL
	apiURL := strings.TrimRight(opts.URL, "/") + "/api/json?tree=jobs[name,url,color,buildable,description,lastBuild[number,url]]"

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add basic auth header
	auth := base64.StdEncoding.EncodeToString([]byte(opts.Auth))
	req.Header.Set("Authorization", "Basic "+auth)
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
	for i, job := range apiResp.Jobs {
		jenkinsJob := JenkinsJob{
			Name:        job.Name,
			URL:         job.URL,
			Color:       job.Color,
			Buildable:   job.Buildable,
			Description: job.Description,
		}

		// If there's a last build, fetch its details
		if job.LastBuild != nil {
			build, err := getBuildDetails(ctx, client, opts.Auth, job.LastBuild.URL)
			if err != nil {
				log.Printf("Warning: failed to get build details for %s: %v", job.Name, err)
				// Still include the job but without detailed build info
				jenkinsJob.LastBuild = &Build{
					Number: job.LastBuild.Number,
					URL:    job.LastBuild.URL,
				}
			} else {
				jenkinsJob.LastBuild = build
			}
		}

		jobs[i] = jenkinsJob
	}

	return jobs, nil
}

// getBuildDetails fetches detailed information about a specific build
func getBuildDetails(ctx context.Context, client *http.Client, auth, buildURL string) (*Build, error) {
	// Add /api/json to the build URL if not already present
	apiURL := strings.TrimRight(buildURL, "/") + "/api/json"

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	// Add basic auth header
	authHeader := base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Set("Authorization", "Basic "+authHeader)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
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
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Build the API URL for computer information (includes executors)
	apiURL := strings.TrimRight(opts.URL, "/") + "/computer/api/json?tree=computer[displayName,executors[currentExecutable[url,fullDisplayName,timestamp],idle,likelyStuck,progress]]"

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add basic auth header
	auth := base64.StdEncoding.EncodeToString([]byte(opts.Auth))
	req.Header.Set("Authorization", "Basic "+auth)
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
			// Format is typically "jobName #buildNumber"
			jobName, buildNumber := parseJobNameAndBuildNumber(executable.FullDisplayName)

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
