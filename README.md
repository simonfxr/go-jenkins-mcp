# Jenkins MCP Server (Go)

**Overview**
- Purpose: Pure Go MCP server exposing Jenkins API functionality as MCP tools.
- Transport: stdio (newline-delimited JSON) via `mcp-go-sdk`.

**Features**
- Tool: `jenkins_get_jobs`
  - Description: Get list of Jenkins jobs with their current status
  - Arguments: None
  - Returns: JSON array of Jenkins jobs with detailed information

- Tool: `jenkins_get_job`
  - Description: Get detailed information about a specific Jenkins job by name
  - Arguments: `name` (required) - Name of the Jenkins job
  - Returns: JSON object with detailed job information

- Tool: `jenkins_get_running_builds`
  - Description: Get list of currently running Jenkins builds
  - Arguments: None
  - Returns: JSON array of running builds with execution details

- Tool: `jenkins_get_build_logs`
  - Description: Get build logs for a specific Jenkins job and build number with pagination support
  - Arguments: 
    - `name` (required) - Name of the Jenkins job
    - `build_number` (required) - Build number to get logs for
    - `offset` (optional, default: 0) - Starting byte offset in the log file
    - `length` (optional, default: 8192) - Maximum number of bytes to retrieve
  - Returns: JSON object with log content and pagination information

- Tool: `jenkins_get_build_log_tail`
  - Description: Get the tail of build logs - useful for seeing why builds failed
  - Arguments:
    - `job_name` (required) - Name of the Jenkins job
    - `build_number` (required) - Build number to get logs for
    - `max_length` (optional, default: 8192) - Maximum number of bytes to retrieve from the end
  - Returns: JSON object with tail log content and metadata

- Tool: `jenkins_start_job`
  - Description: Trigger a Jenkins job build with optional parameters and wait options
  - Arguments:
    - `job_name` (required) - Name/path of the Jenkins job (supports folders)
    - `parameters` (optional) - Object map of build parameters
    - `wait` (optional, default: `none`) - One of `none`, `queued`, `started`
  - Returns: JSON with `jobName`, `queueUrl` (if available), and for `wait=started`, `buildUrl` and `buildNumber`

- Tool: `jenkins_wait_for_running_build`
  - Description: Wait for a running Jenkins build to complete or timeout
  - Arguments:
    - `job_name` (required) - Name of the Jenkins job
    - `build_number` (required) - Build number to wait for
    - `timeout_seconds` (optional, default: 600) - Maximum time to wait in seconds
  - Returns: JSON object with build completion status and timing information

**Job Format**
Each job returned by `jenkins_get_jobs` includes:
```json
{
  "name": "job-name",
  "url": "https://jenkins.example.com/job/job-name/",
  "color": "blue",
  "buildable": true,
  "description": "Job description",
  "lastBuild": {
    "number": 123,
    "url": "https://jenkins.example.com/job/job-name/123/",
    "building": false,
    "result": "SUCCESS",
    "timestamp": 1692614400000,
    "duration": 120000
  },
  "parameters": [
    {
      "name": "MERGE_FEATURE",
      "type": "StringParameterDefinition",
      "description": "Feature branch to merge",
      "defaultValue": "",
      "choices": []
    },
    {
      "name": "BUILD_TYPE",
      "type": "ChoiceParameterDefinition", 
      "description": "Type of build to perform",
      "defaultValue": "release",
      "choices": ["debug", "release", "test"]
    }
  ]
}
```

Note: The `jenkins_get_job` tool returns individual jobs with full parameter information, while `jenkins_get_jobs` returns the job list without parameters for performance.

**Running Build Format**
Each running build returned by `jenkins_get_running_builds` includes:
```json
{
  "jobName": "job-name",
  "buildNumber": 124,
  "url": "https://jenkins.example.com/job/job-name/124/",
  "startTime": 1692614500000,
  "duration": 45000,
  "executor": "master",
  "progress": 75
}
```

**Build Logs Format**
Build logs returned by `jenkins_get_build_logs` include:
```json
{
  "jobName": "job-name",
  "buildNumber": 124,
  "offset": 0,
  "length": 1024,
  "totalSize": 5120,
  "hasMore": true,
  "logs": "Started by user admin\nBuilding in workspace..."
}
```

**Wait for Build Format**
Build wait results returned by `jenkins_wait_for_running_build` include:
```json
{
  "jobName": "job-name",
  "buildNumber": 124,
  "status": "success",
  "result": "SUCCESS",
  "duration": 120000,
  "waitTime": 45000,
  "timedOut": false
}
```

Status values:
- `success`: Build completed successfully
- `failure`: Build failed
- `unstable`: Build completed but with test failures or warnings
- `aborted`: Build was manually aborted
- `timeout`: Wait operation timed out before build completed
- `unknown`: Build completed with an unrecognized result

**Jenkins Color Codes**
- `blue`: Last build was successful
- `red`: Last build failed
- `yellow`: Last build was unstable
- `grey`: Job has never been built
- `disabled`: Job is disabled
- `aborted`: Last build was aborted
- `*_anime`: Job is currently building (e.g., `blue_anime`)

**Requirements**
- CLI: `-url <jenkins_url>` (required) - Jenkins server URL
- CLI: `-auth "<user>:<api_token>"` (required) - Jenkins authentication credentials
- CLI: `-stdio` (default true) for stdio, or `-http <addr>` for Streamable HTTP.

**Run (stdio)**
- Build: `go build -o jenkins-mcp-go .`
- Run (stdio): execute with required parameters; an MCP host (e.g., Claude Desktop) should launch this binary with stdio wiring.

Examples:
- `./jenkins-mcp-go -url "https://jenkins.example.com" -auth "myuser:myapitoken"`
- HTTP mode: `./jenkins-mcp-go -url "https://jenkins.example.com" -auth "myuser:myapitoken" -http :8080`

**Smithery / Hosts**
- Configure your MCP host to run this server over stdio with the required parameters.

**API Details**
- Uses Jenkins REST API `/api/json` endpoint to fetch job list
- Uses Jenkins REST API `/job/{jobName}/api/json` endpoint to fetch specific job details
- Uses Jenkins REST API `/computer/api/json` endpoint to fetch running builds from executors
- Uses Jenkins REST API `/job/{jobName}/{buildNumber}/logText/progressiveText` endpoint for build logs
- Implements smart tail log retrieval by calculating offset from total log size
- Fetches detailed build information for each job's last build
- Implements proper basic authentication
- 30-second timeout for API calls, 60-second timeout for log retrieval
- Graceful error handling for individual build details and missing jobs/builds
- Parses job names and build numbers from executor information
- Supports nested jobs/folders via Jenkins path convention `/job/<seg>/job/<seg>/...` and proper URL escaping
- Supports log pagination with offset and length parameters
- Detects running builds and provides hasMore flag for pagination
- Optimized tail log retrieval for quick failure analysis

**Notes**
- Input validation: enforces required URL and auth parameters
- Auth format: must be "user:api_token" format
- Errors: returned as tool results with `isError=true` for LLM visibility
- Build details are fetched concurrently for better performance

**Transport**
- `-http <addr>` starts Streamable HTTP; otherwise `-stdio` runs by default.
- If `-stdio=false` and no `-http` is provided, the server exits with an error.

**TODO**
- Add more Jenkins tools (get build status, etc.)
- Add filtering options (by job name pattern, status, etc.)
- Add support for Jenkins CSRF protection
- Add SSL certificate validation options
- Add caching for better performance
