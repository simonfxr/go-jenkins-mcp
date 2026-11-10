package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// serverInstructions is sent to MCP clients on initialization.
const serverInstructions = `Jenkins CI tools.

Builds are addressed by job_name (path like "folder/job", or a pasted Jenkins URL) plus build_number, or build=lastBuild|lastFailedBuild|lastSuccessfulBuild.

Typical flows:
- Trigger: jenkins_start_job (validates parameters; wait=started returns the build number, wait=completed blocks until the result). Then jenkins_wait_for_running_build.
- Diagnose a failure: jenkins_get_build_stages (Pipeline jobs: failed stage, step error and step log), then jenkins_grep_build_log (default pattern finds error lines; matches carry line numbers and offsets) and jenkins_get_build_logs with start_line/offset to read around a match. The log tail of a failed Pipeline is usually cleanup noise, not the error.
- Large logs: jenkins_download_build_log writes the whole cleaned log to a local file for grep/read with other tools.

Log offsets and line numbers refer to the cleaned log (console annotations, ANSI escapes and CR removed) and are identical across all log tools and the downloaded file.`

// GetJobsToolArgs are the tool arguments for jenkins_get_jobs.
type GetJobsToolArgs struct {
	Folder string `json:"folder,omitempty" jsonschema:"Only list jobs inside this folder path (default: all jobs, descending up to three folder levels)"`
	Filter string `json:"filter,omitempty" jsonschema:"Only list jobs whose path contains this text (case-insensitive)"`
}

// GetJobsToolResponse is the result payload for jenkins_get_jobs.
type GetJobsToolResponse struct {
	Jobs []Job `json:"jobs"`
}

// GetJobToolArgs are the tool arguments for jenkins_get_job.
type GetJobToolArgs struct {
	JobName   string `json:"job_name" jsonschema:"Job name or folder path (e.g. folder/job), or a Jenkins job URL"`
	MaxBuilds int    `json:"max_builds,omitempty" jsonschema:"Maximum number of recent builds to return (default: 10)" default:"10"`
}

// GetRunningBuildsToolArgs are the tool arguments for jenkins_get_running_builds.
type GetRunningBuildsToolArgs struct{}

// GetRunningBuildsToolResponse contains the list of currently running builds.
type GetRunningBuildsToolResponse struct {
	Builds []RunningBuild `json:"builds"`
	Queued []QueuedBuild  `json:"queuedBuilds,omitempty"`
}

// GetNodesToolArgs are the tool arguments for jenkins_get_nodes.
type GetNodesToolArgs struct{}

// GetNodesToolResponse is the result payload for jenkins_get_nodes.
type GetNodesToolResponse struct {
	Nodes []Node `json:"nodes"`
}

// GetBuildToolArgs are the tool arguments for jenkins_get_build.
type GetBuildToolArgs struct {
	BuildSelector
	ArtifactFilter string `json:"artifact_filter,omitempty" jsonschema:"Only list artifacts whose path contains this text (case-insensitive). Without it the first 20 artifacts are listed"`
}

// GetBuildToolResponse is the build payload returned by jenkins_get_build.
type GetBuildToolResponse struct {
	JobName string `json:"jobName"`
	Build
}

// GetBuildStagesToolArgs are the tool arguments for jenkins_get_build_stages.
type GetBuildStagesToolArgs struct {
	BuildSelector
	MaxStepLogLength int `json:"max_step_log_length,omitempty" jsonschema:"Maximum bytes of log returned per failed step (default: 4096)" default:"4096"`
}

// GetBuildLogsToolArgs are the tool arguments for jenkins_get_build_logs.
type GetBuildLogsToolArgs struct {
	BuildSelector
	Offset     int  `json:"offset,omitempty" jsonschema:"Byte offset to start at; reading begins at the start of the line containing it. Pass nextOffset of the previous call to continue (default: 0)" default:"0"`
	StartLine  int  `json:"start_line,omitempty" jsonschema:"1-based line number to start at (alternative to offset)"`
	Length     int  `json:"length,omitempty" jsonschema:"Maximum bytes to return; only whole lines are returned (default: 8192)" default:"8192"`
	MaxLines   int  `json:"max_lines,omitempty" jsonschema:"Maximum number of lines to return (default: limited by length only)"`
	Timestamps bool `json:"timestamps,omitempty" jsonschema:"Keep the per-line timestamp prefix of Pipeline logs (default: false)"`
}

// GetBuildLogTailToolArgs are the tool arguments for jenkins_get_build_log_tail.
type GetBuildLogTailToolArgs struct {
	BuildSelector
	MaxLength  int  `json:"max_length,omitempty" jsonschema:"Maximum bytes from the end of the log; only whole lines are returned (default: 8192)" default:"8192"`
	MaxLines   int  `json:"max_lines,omitempty" jsonschema:"Maximum number of lines to return (default: limited by max_length only)"`
	Timestamps bool `json:"timestamps,omitempty" jsonschema:"Keep the per-line timestamp prefix of Pipeline logs (default: false)"`
}

// GrepBuildLogToolArgs are the tool arguments for jenkins_grep_build_log.
type GrepBuildLogToolArgs struct {
	BuildSelector
	Pattern    string `json:"pattern,omitempty" jsonschema:"Regular expression (RE2 syntax) matched against each line. Default: a pattern for common error lines (error, fatal, exception, failed, exit code N, ...)"`
	Exclude    string `json:"exclude,omitempty" jsonschema:"Regular expression; matching lines are skipped"`
	IgnoreCase bool   `json:"ignore_case,omitempty" jsonschema:"Case-insensitive matching for pattern and exclude (default: false)"`
	Context    int    `json:"context,omitempty" jsonschema:"Lines of context to include before and after each match (default: 0)" default:"0"`
	MaxMatches int    `json:"max_matches,omitempty" jsonschema:"Maximum number of matches to return (default: 20)" default:"20"`
	Tail       bool   `json:"tail,omitempty" jsonschema:"Return the last max_matches matches instead of the first (default: false)"`
	Offset     int    `json:"offset,omitempty" jsonschema:"Byte offset to start searching at; pass nextOffset of a truncated result to get further matches (default: 0)" default:"0"`
	Timestamps bool   `json:"timestamps,omitempty" jsonschema:"Keep the per-line timestamp prefix of Pipeline logs; it then also takes part in matching (default: false)"`
}

// DownloadBuildLogToolArgs are the tool arguments for jenkins_download_build_log.
type DownloadBuildLogToolArgs struct {
	BuildSelector
	Path   string `json:"path,omitempty" jsonschema:"Destination file on the machine running this server (default: the log cache file, or a temporary file)"`
	Output string `json:"output,omitempty" jsonschema:"file (default): write a file and return its path. text: return the entire log as plain text instead, e.g. for redirecting into a file" default:"file"`
}

// DownloadArtifactToolArgs are the tool arguments for jenkins_download_artifact.
type DownloadArtifactToolArgs struct {
	BuildSelector
	Artifact string `json:"artifact" jsonschema:"Relative path of the artifact as listed by jenkins_get_build"`
	Path     string `json:"path,omitempty" jsonschema:"Destination file on the machine running this server (default: a file below the temporary directory)"`
}

// DownloadArtifactToolResponse is the result payload for jenkins_download_artifact.
type DownloadArtifactToolResponse struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	Artifact    string `json:"artifact"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
}

// StartJobToolArgs are the tool arguments for jenkins_start_job.
type StartJobToolArgs struct {
	JobName        string         `json:"job_name" jsonschema:"Job name or folder path (e.g. folder/job), or a Jenkins job URL"`
	Parameters     map[string]any `json:"parameters,omitempty" jsonschema:"Build parameters as name/value map. Names and choice values are validated against the job; omitted parameters use the job defaults"`
	FromBuild      int            `json:"from_build,omitempty" jsonschema:"Re-run: start with the parameters of this earlier build number; values in parameters override them"`
	Wait           string         `json:"wait,omitempty" jsonschema:"none: return once queued. started (default): wait until the build left the queue and has a build number. completed: wait until the build finished" default:"started"`
	TimeoutSeconds int            `json:"timeout_seconds,omitempty" jsonschema:"Maximum total time to wait (default: 30 for wait=started, 600 for wait=completed). On timeout the current state is returned; the build keeps going"`
}

// StartJobToolResponse represents the response from jenkins_start_job.
type StartJobToolResponse struct {
	JobName       string            `json:"jobName"`
	Status        string            `json:"status"`                  // queued, started, completed, cancelled
	AlreadyQueued bool              `json:"alreadyQueued,omitempty"` // an identical build was already queued; no new one was added
	QueueID       int               `json:"queueId,omitempty"`
	Why           string            `json:"why,omitempty"` // why the build is still queued
	BuildNumber   int               `json:"buildNumber,omitempty"`
	BuildURL      string            `json:"buildUrl,omitempty"`
	Parameters    map[string]string `json:"parameters,omitempty"` // parameters sent; all others use job defaults
	TimedOut      bool              `json:"timedOut,omitempty"`
	Result        string            `json:"result,omitempty"`
	Duration      DurationMS        `json:"duration,omitzero"`
	Failure       *FailureSummary   `json:"failure,omitempty"`
	Note          string            `json:"note,omitempty"`
}

// GetQueueItemToolArgs are the tool arguments for jenkins_get_queue_item.
type GetQueueItemToolArgs struct {
	QueueID int    `json:"queue_id" jsonschema:"Jenkins queue item ID"`
	JobName string `json:"job_name,omitempty" jsonschema:"Job the item belongs to. Lets the build be found after Jenkins has forgotten the queue item (5 minutes after it left the queue)"`
}

// WaitForQueueItemToolArgs are the tool arguments for jenkins_wait_for_queue_item.
type WaitForQueueItemToolArgs struct {
	QueueID        int    `json:"queue_id" jsonschema:"Jenkins queue item ID"`
	JobName        string `json:"job_name,omitempty" jsonschema:"Job the item belongs to. Lets the build be found after Jenkins has forgotten the queue item (5 minutes after it left the queue)"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"Maximum time to wait in seconds (default: 30)" default:"30"`
}

// WaitForQueueItemToolResponse represents the response from jenkins_wait_for_queue_item.
type WaitForQueueItemToolResponse struct {
	Status    string     `json:"status"` // started, cancelled, or queued (timed out)
	TimedOut  bool       `json:"timedOut"`
	WaitTime  DurationMS `json:"waitTime"`
	QueueItem *QueueItem `json:"queueItem,omitempty"`
	Build     *Build     `json:"build,omitempty"`
}

// WaitForRunningBuildToolArgs are the tool arguments for jenkins_wait_for_running_build.
type WaitForRunningBuildToolArgs struct {
	BuildSelector
	TimeoutSeconds int `json:"timeout_seconds,omitempty" jsonschema:"Maximum time to wait in seconds (default: 600). On timeout status is running; call again to keep waiting" default:"600"`
}

// WaitForRunningBuildToolResponse represents the response from jenkins_wait_for_running_build.
type WaitForRunningBuildToolResponse struct {
	JobName           string          `json:"jobName"`
	BuildNumber       int             `json:"buildNumber"`
	URL               string          `json:"url,omitempty"`
	Status            string          `json:"status"`           // success, failure, unstable, aborted, not_built, or running (timed out)
	Result            string          `json:"result,omitempty"` // Jenkins result (SUCCESS, FAILURE, UNSTABLE, ABORTED, NOT_BUILT)
	Duration          DurationMS      `json:"duration"`         // build duration (so far, when still running)
	EstimatedDuration DurationMS      `json:"estimatedDuration,omitzero"`
	WaitTime          DurationMS      `json:"waitTime"`
	TimedOut          bool            `json:"timedOut"`
	Failure           *FailureSummary `json:"failure,omitempty"` // present when the build did not succeed
}

// StopBuildToolArgs are the tool arguments for jenkins_stop_build.
type StopBuildToolArgs struct {
	JobName     string `json:"job_name,omitempty" jsonschema:"Job name or folder path, or a Jenkins build URL. Required unless queue_id is given"`
	BuildNumber int    `json:"build_number,omitempty" jsonschema:"Number of the running build to stop"`
	Build       string `json:"build,omitempty" jsonschema:"Alternative to build_number: lastBuild"`
	QueueID     int    `json:"queue_id,omitempty" jsonschema:"Cancel this queue item instead; if it already started, the resulting build is stopped"`
}

// StopBuildToolResponse represents the response from jenkins_stop_build.
type StopBuildToolResponse struct {
	JobName     string `json:"jobName,omitempty"`
	BuildNumber int    `json:"buildNumber,omitempty"`
	QueueID     int    `json:"queueId,omitempty"`
	Status      string `json:"status"`           // stopped, stopping (abort requested, still shutting down), not_running, cancelled_in_queue
	Result      string `json:"result,omitempty"` // build result once it is no longer running
}

// SearchBuildsToolArgs are the tool arguments for jenkins_search_builds.
type SearchBuildsToolArgs struct {
	JobName     string   `json:"job_name" jsonschema:"Job name or folder path (e.g. folder/job), or a Jenkins job URL"`
	Result      string   `json:"result,omitempty" jsonschema:"Filter by build result: SUCCESS, FAILURE, UNSTABLE, ABORTED, NOT_BUILT, or BUILDING for builds in progress"`
	Params      []string `json:"params,omitempty" jsonschema:"Filter by build parameters: key=value (equal), key!=value (not equal) or key~=regex (RE2 match). An empty value (key=) matches an empty or unset parameter"`
	Limit       int      `json:"limit,omitempty" jsonschema:"Maximum number of matching builds to return (default: 5)" default:"5"`
	MaxLookback int      `json:"max_lookback,omitempty" jsonschema:"Maximum number of most recent builds to scan (default: 100)" default:"100"`
}

// SearchBuildsToolResponse is the result payload for jenkins_search_builds.
type SearchBuildsToolResponse struct {
	JobName string  `json:"jobName"`
	Builds  []Build `json:"builds"`  // newest first
	Scanned int     `json:"scanned"` // how many builds were scanned
}

// progressFunc reports progress of a long-running tool call.
type progressFunc func(message string)

// newProgress returns a progressFunc sending MCP progress notifications (at
// most one every few seconds) when the client asked for them. Clients can use
// them to keep long waits from running into request timeouts.
func newProgress(ctx context.Context, req *mcp.CallToolRequest) progressFunc {
	if req == nil || req.Session == nil || req.Params == nil {
		return func(string) {}
	}
	token := req.Params.GetProgressToken()
	if token == nil {
		return func(string) {}
	}
	var (
		count float64
		last  time.Time
	)
	return func(message string) {
		if time.Since(last) < 5*time.Second {
			return
		}
		last = time.Now()
		count++
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: token, Progress: count, Message: message})
	}
}

func readOnlyTool(name, title, description string) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true}}
}

func (opts *JenkinsOptions) addTools(s *mcp.Server) {
	notDestructive := false

	addTool(s, readOnlyTool("jenkins_get_jobs", "List Jenkins jobs",
		"List Jenkins jobs (including jobs in folders) with their status and last build. Use filter to narrow by name."),
		func(ctx context.Context, req *mcp.CallToolRequest, args GetJobsToolArgs) (*mcp.CallToolResult, any, error) {
			folder, err := optionalJobRef(args.Folder)
			if err != nil {
				return nil, nil, err
			}
			jobs, err := opts.getJenkinsJobs(ctx, folder, args.Filter)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(GetJobsToolResponse{Jobs: jobs})
		})

	addTool(s, readOnlyTool("jenkins_get_job", "Get Jenkins job",
		"Get a job's parameter definitions (names, types, defaults, choices), recent builds and queued builds. Recent builds list only parameters that differ from the job defaults (nonDefaultParameters)."),
		func(ctx context.Context, req *mcp.CallToolRequest, args GetJobToolArgs) (*mcp.CallToolResult, any, error) {
			jobName, _, err := parseJobRef(args.JobName)
			if err != nil {
				return nil, nil, err
			}
			if args.MaxBuilds <= 0 {
				args.MaxBuilds = 10
			}
			job, err := opts.getJenkinsJob(ctx, jobName, args.MaxBuilds)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(job)
		})

	addTool(s, readOnlyTool("jenkins_search_builds", "Search Jenkins builds",
		"Search a job's builds by result and/or build parameters, newest first. Use to find e.g. the latest successful build of a branch. Builds list only parameters that differ from the job defaults (nonDefaultParameters)."),
		func(ctx context.Context, req *mcp.CallToolRequest, args SearchBuildsToolArgs) (*mcp.CallToolResult, any, error) {
			jobName, _, err := parseJobRef(args.JobName)
			if err != nil {
				return nil, nil, err
			}
			if args.Limit <= 0 {
				args.Limit = 5
			}
			if args.MaxLookback <= 0 {
				args.MaxLookback = 100
			}
			res, err := opts.searchBuilds(ctx, jobName, args)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(res)
		})

	addTool(s, readOnlyTool("jenkins_get_build", "Get Jenkins build",
		"Get details of a build: state, result, duration, all parameters, causes (who/what started it), node, SCM changes and artifacts."),
		func(ctx context.Context, req *mcp.CallToolRequest, args GetBuildToolArgs) (*mcp.CallToolResult, any, error) {
			jobName, number, err := opts.resolveBuild(ctx, args.BuildSelector)
			if err != nil {
				return nil, nil, err
			}
			build, err := opts.getBuildDetails(ctx, jobName, number, args.ArtifactFilter)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(GetBuildToolResponse{JobName: jobName, Build: *build})
		})

	addTool(s, readOnlyTool("jenkins_get_build_stages", "Get Pipeline stages of a build",
		"Get the Pipeline stages of a build with status and duration. For stages that failed it includes the failing steps with their error message and the end of that step's log - usually the fastest way to find out why a Pipeline build failed. Works while the build is running. Pipeline jobs only."),
		func(ctx context.Context, req *mcp.CallToolRequest, args GetBuildStagesToolArgs) (*mcp.CallToolResult, any, error) {
			jobName, number, err := opts.resolveBuild(ctx, args.BuildSelector)
			if err != nil {
				return nil, nil, err
			}
			if args.MaxStepLogLength <= 0 {
				args.MaxStepLogLength = 4096
			}
			stages, err := opts.getBuildStages(ctx, jobName, number, args.MaxStepLogLength, false)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(stages)
		})

	addTool(s, readOnlyTool("jenkins_get_build_logs", "Read Jenkins build log",
		"Read a portion of a build log as whole lines, starting at a byte offset or line number. Returns nextOffset for reading on; on a running build, repeat with nextOffset to follow the log. Use jenkins_grep_build_log to locate interesting lines first."),
		func(ctx context.Context, req *mcp.CallToolRequest, args GetBuildLogsToolArgs) (*mcp.CallToolResult, any, error) {
			jobName, number, err := opts.resolveBuild(ctx, args.BuildSelector)
			if err != nil {
				return nil, nil, err
			}
			if args.Length <= 0 {
				args.Length = 8192
			}
			logs, err := opts.getBuildLogs(ctx, jobName, number, args)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(logs)
		})

	addTool(s, readOnlyTool("jenkins_get_build_log_tail", "Read end of Jenkins build log",
		"Read the last lines of a build log. Note: the end of a failed Pipeline log is often post-failure cleanup; use jenkins_get_build_stages or jenkins_grep_build_log to find the actual error."),
		func(ctx context.Context, req *mcp.CallToolRequest, args GetBuildLogTailToolArgs) (*mcp.CallToolResult, any, error) {
			jobName, number, err := opts.resolveBuild(ctx, args.BuildSelector)
			if err != nil {
				return nil, nil, err
			}
			if args.MaxLength <= 0 {
				args.MaxLength = 8192
			}
			logs, err := opts.getBuildLogTail(ctx, jobName, number, args)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(logs)
		})

	addTool(s, readOnlyTool("jenkins_grep_build_log", "Search Jenkins build log",
		"Search a build log with a regular expression; without pattern it finds common error lines. Each match has its line number and byte offset, usable as start_line/offset of jenkins_get_build_logs to read the surrounding log. totalMatches counts all matches even when only max_matches are returned."),
		func(ctx context.Context, req *mcp.CallToolRequest, args GrepBuildLogToolArgs) (*mcp.CallToolResult, any, error) {
			jobName, number, err := opts.resolveBuild(ctx, args.BuildSelector)
			if err != nil {
				return nil, nil, err
			}
			if args.MaxMatches <= 0 {
				args.MaxMatches = 20
			}
			res, err := opts.grepBuildLog(ctx, jobName, number, args)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(res)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_download_build_log",
		Description: "Fetch the complete cleaned build log. By default it is written to a local file whose path is returned, for use with grep/read tools; line numbers and offsets match the other log tools. With output=text the whole log is returned as plain text instead (may be large).",
		Annotations: &mcp.ToolAnnotations{Title: "Download Jenkins build log", DestructiveHint: &notDestructive, IdempotentHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, args DownloadBuildLogToolArgs) (*mcp.CallToolResult, any, error) {
			jobName, number, err := opts.resolveBuild(ctx, args.BuildSelector)
			if err != nil {
				return nil, nil, err
			}
			switch strings.ToLower(strings.TrimSpace(args.Output)) {
			case "", "file":
				res, err := opts.downloadBuildLog(ctx, jobName, number, strings.TrimSpace(args.Path))
				if err != nil {
					return nil, nil, err
				}
				return structuredResult(res)
			case "text":
				snap, err := opts.getLog(ctx, jobName, number)
				if err != nil {
					return nil, nil, err
				}
				// Plain text only, so that redirected tool output is the log itself.
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(snap.Data)}}}, nil, nil
			}
			return nil, nil, fmt.Errorf("invalid output %q: expected file or text", args.Output)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_download_artifact",
		Description: "Download a build artifact to a local file and return its path. Artifact paths are listed by jenkins_get_build.",
		Annotations: &mcp.ToolAnnotations{Title: "Download Jenkins build artifact", DestructiveHint: &notDestructive, IdempotentHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, args DownloadArtifactToolArgs) (*mcp.CallToolResult, any, error) {
			jobName, number, err := opts.resolveBuild(ctx, args.BuildSelector)
			if err != nil {
				return nil, nil, err
			}
			path, size, err := opts.downloadArtifact(ctx, jobName, number, args.Artifact, strings.TrimSpace(args.Path))
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(DownloadArtifactToolResponse{JobName: jobName, BuildNumber: number, Artifact: args.Artifact, Path: path, Size: size})
		})

	addTool(s, readOnlyTool("jenkins_get_running_builds", "List running and queued Jenkins builds",
		"List currently running builds (with node and progress) and queued builds (with the reason they are waiting)."),
		func(ctx context.Context, req *mcp.CallToolRequest, args GetRunningBuildsToolArgs) (*mcp.CallToolResult, any, error) {
			running, err := opts.getRunningBuilds(ctx)
			if err != nil {
				return nil, nil, err
			}
			// Degrade gracefully if the queue endpoint is unavailable.
			queued, _ := opts.getQueuedBuilds(ctx)
			return structuredResult(GetRunningBuildsToolResponse{Builds: running, Queued: queued})
		})

	addTool(s, readOnlyTool("jenkins_get_nodes", "List Jenkins nodes",
		"List Jenkins nodes (agents) with online state, labels and executor usage. Useful to understand why a build is stuck in the queue waiting for a node or label."),
		func(ctx context.Context, req *mcp.CallToolRequest, args GetNodesToolArgs) (*mcp.CallToolResult, any, error) {
			nodes, err := opts.getNodes(ctx)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(GetNodesToolResponse{Nodes: nodes})
		})

	addTool(s, &mcp.Tool{
		Name: "jenkins_start_job",
		Description: "Trigger a build. Parameter names and choice values are validated first (see jenkins_get_job for definitions); omitted parameters use the job defaults. from_build re-runs an earlier build with the same parameters. " +
			"By default waits until the build left the queue and returns its build number; if it is still queued then, status is queued with the reason (follow up with jenkins_wait_for_queue_item). " +
			"alreadyQueued=true means an identical build was already waiting in the queue and no new one was added.",
		Annotations: &mcp.ToolAnnotations{Title: "Start Jenkins build"}},
		func(ctx context.Context, req *mcp.CallToolRequest, args StartJobToolArgs) (*mcp.CallToolResult, any, error) {
			res, err := opts.startJob(ctx, args, newProgress(ctx, req))
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(res)
		})

	addTool(s, &mcp.Tool{
		Name:        "jenkins_stop_build",
		Description: "Abort a running build (job_name + build_number), or cancel a queued build (queue_id). Reports what happened: stopped, stopping (abort requested but the build is still shutting down), not_running, or cancelled_in_queue.",
		Annotations: &mcp.ToolAnnotations{Title: "Stop Jenkins build", IdempotentHint: true}},
		func(ctx context.Context, req *mcp.CallToolRequest, args StopBuildToolArgs) (*mcp.CallToolResult, any, error) {
			if args.QueueID > 0 {
				jobName, err := optionalJobRef(args.JobName)
				if err != nil {
					return nil, nil, err
				}
				res, err := opts.stopQueued(ctx, args.QueueID, jobName)
				if err != nil {
					return nil, nil, err
				}
				return structuredResult(res)
			}
			jobName, number, err := opts.resolveBuild(ctx, BuildSelector{JobName: args.JobName, BuildNumber: args.BuildNumber, Build: args.Build})
			if err != nil {
				return nil, nil, err
			}
			res, err := opts.stopBuild(ctx, jobName, number)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(res)
		})

	addTool(s, readOnlyTool("jenkins_get_queue_item", "Get Jenkins queue item",
		"Get the current state of a queue item: queued (with reason), started (with the assigned build) or cancelled."),
		func(ctx context.Context, req *mcp.CallToolRequest, args GetQueueItemToolArgs) (*mcp.CallToolResult, any, error) {
			if args.QueueID <= 0 {
				return nil, nil, fmt.Errorf("missing or invalid required argument: queue_id (must be > 0)")
			}
			jobName, err := optionalJobRef(args.JobName)
			if err != nil {
				return nil, nil, err
			}
			item, err := opts.getQueueItem(ctx, args.QueueID, jobName)
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(item)
		})

	addTool(s, readOnlyTool("jenkins_wait_for_queue_item", "Wait for Jenkins queue item",
		"Wait until a queued build starts (returns its build number), is cancelled, or the timeout expires (status queued, with the reason it is still waiting)."),
		func(ctx context.Context, req *mcp.CallToolRequest, args WaitForQueueItemToolArgs) (*mcp.CallToolResult, any, error) {
			if args.QueueID <= 0 {
				return nil, nil, fmt.Errorf("missing or invalid required argument: queue_id (must be > 0)")
			}
			jobName, err := optionalJobRef(args.JobName)
			if err != nil {
				return nil, nil, err
			}
			if args.TimeoutSeconds <= 0 {
				args.TimeoutSeconds = 30
			}
			res, err := opts.waitForQueueItem(ctx, args.QueueID, jobName, time.Duration(args.TimeoutSeconds)*time.Second, newProgress(ctx, req))
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(res)
		})

	addTool(s, readOnlyTool("jenkins_wait_for_running_build", "Wait for Jenkins build",
		"Wait until a build finishes or the timeout expires. Returns immediately for finished builds. When the build did not succeed, the result includes a failure summary (failed Pipeline stage, step error and step log, or matching error lines). On timeout status is running; call again to keep waiting."),
		func(ctx context.Context, req *mcp.CallToolRequest, args WaitForRunningBuildToolArgs) (*mcp.CallToolResult, any, error) {
			jobName, number, err := opts.resolveBuild(ctx, args.BuildSelector)
			if err != nil {
				return nil, nil, err
			}
			if args.TimeoutSeconds <= 0 {
				args.TimeoutSeconds = 600
			}
			res, err := opts.waitForBuild(ctx, jobName, number, time.Duration(args.TimeoutSeconds)*time.Second, newProgress(ctx, req))
			if err != nil {
				return nil, nil, err
			}
			return structuredResult(res)
		})
}

func optionalJobRef(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil
	}
	job, _, err := parseJobRef(s)
	return job, err
}

func addTool[In any](s *mcp.Server, t *mcp.Tool, h mcp.ToolHandlerFor[In, any]) {
	t.InputSchema = jsonschemaForExt[In]()
	mcp.AddTool(s, t, h)
}

// structuredResult returns out both as structured content and as JSON text
// (without HTML escaping, which only costs tokens).
func structuredResult(out any) (*mcp.CallToolResult, any, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.TrimSuffix(buf.String(), "\n")}},
	}, out, nil
}
