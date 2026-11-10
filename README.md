# Jenkins MCP Server (Go)

Pure Go [MCP](https://modelcontextprotocol.io) server that lets coding agents drive Jenkins: trigger builds, wait for them, and find out why they failed without wading through raw console output.

- Transport: stdio or Streamable HTTP, via the official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk).
- Works with freestyle and Pipeline jobs, folders included.

## Tools

Builds are addressed by `job_name` plus `build_number`. Wherever a build is expected you can instead pass

- `build`: `lastBuild`, `lastCompletedBuild`, `lastSuccessfulBuild`, `lastFailedBuild` or `lastUnsuccessfulBuild`
- a pasted Jenkins URL as `job_name`, e.g. `https://jenkins.example.com/job/folder/job/app/123/console`

Responses always carry the resolved `jobName` and `buildNumber`.

| Tool | Purpose |
|------|---------|
| `jenkins_get_jobs` | List jobs (descends into folders), optional `folder` and `filter` |
| `jenkins_get_job` | Parameter definitions, recent builds, queued builds |
| `jenkins_search_builds` | Find builds by result and parameters |
| `jenkins_get_build` | Build details: state, parameters, causes, node, changes, artifacts |
| `jenkins_get_build_stages` | Pipeline stages; failed steps with error and step log |
| `jenkins_get_build_logs` | Read the log by byte offset or line number |
| `jenkins_get_build_log_tail` | Read the end of the log |
| `jenkins_grep_build_log` | Regex search in the log; default pattern finds error lines |
| `jenkins_download_build_log` | Write the whole log to a local file (or return it as plain text) |
| `jenkins_download_artifact` | Save a build artifact to a local file |
| `jenkins_get_running_builds` | Running and queued builds |
| `jenkins_get_nodes` | Nodes with online state, labels, executor usage |
| `jenkins_start_job` | Trigger a build with validated parameters, optionally wait |
| `jenkins_stop_build` | Abort a running build or cancel a queued one |
| `jenkins_get_queue_item` | State of a queue item |
| `jenkins_wait_for_queue_item` | Wait until a queued build starts |
| `jenkins_wait_for_running_build` | Wait until a build finishes; summarizes failures |

All read-only tools are annotated with `readOnlyHint` so hosts can auto-approve them.

### Starting builds

`jenkins_start_job`

- `job_name` (required)
- `parameters`: name/value map. Names and choice values are checked against the job's parameter definitions *before* anything is triggered - Jenkins itself silently ignores unknown names and would start a build with defaults. Omitted parameters use the job defaults.
- `from_build`: re-run with the parameters of an earlier build; `parameters` override them.
- `wait`: `none` (return once queued), `started` (default: wait for the build number), `completed` (wait for the result).
- `timeout_seconds`: default 30 for `started`, 600 for `completed`. On timeout the current state is returned and the build keeps going.

```json
{
  "jobName": "app",
  "status": "started",
  "queueId": 30617,
  "buildNumber": 124,
  "buildUrl": "https://jenkins.example.com/job/app/124/",
  "parameters": {"BRANCH": "feature/x"}
}
```

- `status`: `queued`, `started`, `completed` or `cancelled`. While `queued`, `why` holds Jenkins' reason.
- `alreadyQueued: true`: an identical build was already waiting in the queue, so Jenkins added no new one; `queueId` refers to the existing item.
- With `wait=completed`: `result`, `duration`, and `failure` (see below) when the build did not succeed.

`jenkins_stop_build` takes `job_name` + `build_number`, or a `queue_id`. It reports what happened: `stopped`, `stopping` (abort requested, build still shutting down), `not_running`, or `cancelled_in_queue`. A `queue_id` whose build already started stops that build.

`jenkins_get_queue_item` / `jenkins_wait_for_queue_item` take `queue_id` and optionally `job_name`. Jenkins forgets queue items five minutes after they leave the queue; with `job_name` the build is then found through its recorded queue ID.

### Waiting

`jenkins_wait_for_running_build` (`timeout_seconds`, default 600) returns immediately for finished builds and reports missing builds right away instead of waiting out the timeout.

```json
{
  "jobName": "app",
  "buildNumber": 124,
  "status": "failure",
  "result": "FAILURE",
  "duration": "52s",
  "waitTime": "41s",
  "timedOut": false,
  "failure": {
    "failedStages": [{
      "id": "13", "name": "build", "status": "FAILED", "duration": "50s",
      "failedSteps": [{
        "id": "26", "name": "Shell Script", "description": "make all", "status": "FAILED",
        "error": "script returned exit code 2",
        "log": "+ make all\nfoo.c:12: error: expected ';'\n"
      }]
    }]
  }
}
```

- `status`: `success`, `failure`, `unstable`, `aborted`, `not_built`, or `running` when the wait timed out (`timedOut: true`) - call again to keep waiting.
- `failure`: for Pipeline builds the failed stages and steps; otherwise `errorLines` (last matches of the default error pattern) and `logTail`.
- Clients that send a progress token receive progress notifications while waiting, which keeps long waits from hitting request timeouts.

### Logs

The server keeps a *cleaned* copy of each build log: Jenkins' hidden console annotations and ANSI escape sequences are removed, line endings are LF, and carriage-return progress output is collapsed to its final state. **Byte offsets and line numbers refer to this cleaned log and are identical across all log tools and the downloaded file.**

All log tools return whole lines. Pipeline logs carry a `[2026-11-10T08:19:16.593Z] ` prefix on every line; it is dropped from tool output unless `timestamps: true` (the downloaded file always keeps it).

`jenkins_get_build_logs`

- `offset` (default 0) or `start_line` (1-based); reading starts at the beginning of the line containing `offset`
- `length` (default 8192 bytes), `max_lines`

```json
{
  "jobName": "app", "buildNumber": 124,
  "offset": 20866, "nextOffset": 22047,
  "startLine": 260, "endLine": 270,
  "totalSize": 24856, "totalLines": 311,
  "complete": true, "hasMore": true,
  "logs": "..."
}
```

Pass `nextOffset` as `offset` to continue. `complete` is false while the build is still running; then `hasMore` stays true and repeating the call with `nextOffset` follows the log.

`jenkins_get_build_log_tail`: `max_length` (default 8192 bytes), `max_lines`. Same result shape. The end of a failed Pipeline log is often post-failure cleanup, so prefer the stages or grep tool to locate errors.

`jenkins_grep_build_log`

- `pattern`: RE2 regular expression. Default: a pattern for common error lines (`error`, `fatal`, `exception`, `failed`, `exit code N`, ...)
- `exclude`: lines matching this regex are skipped
- `ignore_case`, `context` (lines before/after, default 0), `max_matches` (default 20)
- `tail`: return the last matches instead of the first
- `offset`: start searching here; a truncated result returns `nextOffset` for the following matches

```json
{
  "jobName": "app", "buildNumber": 124,
  "totalMatches": 5, "truncated": true, "nextOffset": 24149,
  "totalSize": 24856, "totalLines": 311, "complete": true,
  "matches": [
    {"line": 260, "offset": 20866, "text": "PHP Fatal error: Uncaught Exception: Merge failed",
     "before": ["MERGING feature ..."], "after": ["CONFLICT (content): Merge conflict in bootstrap.sh"]}
  ]
}
```

Use a match's `line` or `offset` as `start_line` / `offset` of `jenkins_get_build_logs` to read around it.

`jenkins_download_build_log`

- `output: "file"` (default) writes the full cleaned log and returns `path`, `size`, `lines`, `complete`. `path` chooses the destination; otherwise the log cache file is used.
- `output: "text"` returns the entire log as plain text and nothing else, so tool output can be redirected straight into a file.

Files are written on the machine running the server, so file output is only useful with the stdio transport or a local HTTP server.

#### Log cache

Logs of finished builds never change and are cached as plain files:

1. `-cache-dir`, else `$JENKINS_MCP_CACHE_DIR`, else `<user cache dir>/go-jenkins-mcp` (`~/.cache/go-jenkins-mcp` on Linux)
2. if that cannot be written (read-only home, sandbox): a private `go-jenkins-mcp-<uid>` directory below the temporary directory
3. if that fails as well: memory only

The cache is an optimization, never a requirement - every tool works in all three cases. `-cache-dir none` disables the disk cache. Cached logs older than 30 days are removed. Logs of running builds are held in memory and extended incrementally.

### Pipeline stages

`jenkins_get_build_stages` (`max_step_log_length`, default 4096) lists stages with status and duration. Stages that failed include their failing steps with the error message and the end of that step's own log - usually the shortest path to the cause of a failed Pipeline build. Works on running builds too. Requires the Pipeline Stage View plugin (`pipeline-rest-api`); for other builds it explains that no stage information exists.

### Jobs and builds

`jenkins_get_job` (`job_name`, `max_builds` default 10) returns parameter definitions and recent builds:

```json
{
  "name": "app",
  "url": "https://jenkins.example.com/job/app/",
  "color": "blue",
  "buildable": true,
  "recentBuilds": [
    {"number": 124, "url": "...", "building": false, "result": "SUCCESS",
     "timestamp": "2026-11-10T08:48:51Z", "duration": "6m51s", "estimatedDuration": "8m22s",
     "nonDefaultParameters": {"BRANCH": "feature/x"}}
  ],
  "parameters": [
    {"name": "BRANCH", "type": "StringParameterDefinition", "description": "Branch to build", "defaultValue": "main"},
    {"name": "TARGET", "type": "ChoiceParameterDefinition", "defaultValue": "all", "choices": ["all", "arm"]}
  ]
}
```

Build listings (`jenkins_get_job`, `jenkins_search_builds`) show only `nonDefaultParameters`: parameters whose value differs from the job's current default. `jenkins_get_build` returns all `parameters`, plus `causes`, `builtOn`, `queueId`, `changes` and `artifacts` (first 20; use `artifact_filter` to search them).

`jenkins_search_builds`

- `result`: `SUCCESS`, `FAILURE`, `UNSTABLE`, `ABORTED`, `NOT_BUILT`, or `BUILDING`
- `params`: `key=value` (equal), `key!=value` (not equal), `key~=regex` (RE2 match); `key=` matches an empty or unset parameter
- `limit` (default 5), `max_lookback` (default 100, may exceed 100)

`jenkins_get_running_builds` lists running builds (`jobName`, `buildNumber`, `url`, `node`, `startTime`, `duration`, `progress`) and `queuedBuilds` (`queueId`, `why`, ...).

Job `color` values: `blue` success, `red` failed, `yellow` unstable, `aborted`, `disabled`, `notbuilt`/`grey` no result yet; a `_anime` suffix means a build is running.

Timestamps are RFC3339 strings; durations are human-readable (`45s`, `2m5s`).

## Running

- `-url <jenkins_url>` (required)
- `-auth "<user>:<api_token>"` or environment `JENKINS_MCP_AUTH` (the flag takes precedence)
- `-stdio` (default) or `-http <addr>` for Streamable HTTP
- `-cache-dir <dir>` log cache location, `none` to disable (see [Log cache](#log-cache))
- `-version` prints the version and exits

```sh
JENKINS_MCP_AUTH="myuser:myapitoken" go-jenkins-mcp -url "https://jenkins.example.com"
JENKINS_MCP_AUTH="myuser:myapitoken" go-jenkins-mcp -url "https://jenkins.example.com" -http :8080
```

Use an API token rather than a password. Tokens are exempt from Jenkins' CSRF protection; with a password the server fetches a crumb when Jenkins asks for one.

## Install / Build

- Install: `go install github.com/simonfxr/go-jenkins-mcp@latest`
- With Nix: `nix run github:simonfxr/go-jenkins-mcp -- -url ...` or `nix profile install github:simonfxr/go-jenkins-mcp`
- From source: `go build` (produces `./go-jenkins-mcp`), `go test ./...`

## Behaviour notes

- Credentials are only ever sent to the configured `-url`; pasted URLs are reduced to their job path.
- GET requests are retried on connection errors and HTTP 502/503/504. POST requests (start, stop) are never retried and their redirects are not followed, because Jenkins encodes the outcome in the redirect.
- Jenkins' HTML error pages are reduced to a short text message.
- Errors are returned as tool results with `isError=true` so the model can read them.
- API calls time out after 30 seconds, log and artifact downloads after 5 minutes.
