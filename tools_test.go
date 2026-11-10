package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestParseJobRef(t *testing.T) {
	cases := []struct {
		in, job, build string
		wantErr        bool
	}{
		{"all_mdsprint", "all_mdsprint", "", false},
		{" /folder/sub/job/ ", "folder/sub/job", "", false},
		{"https://ci.example.com/job/all_mdsprint/17403/console", "all_mdsprint", "17403", false},
		{"https://ci.example.com/jenkins/job/folder/job/my%20job/", "folder/my job", "", false},
		{"https://ci.example.com/job/a/job/b/lastFailedBuild/", "a/b", "lastFailedBuild", false},
		{"https://ci.example.com/view/all/", "", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		job, build, err := parseJobRef(c.in)
		if (err != nil) != c.wantErr || job != c.job || build != c.build {
			t.Errorf("parseJobRef(%q) = %q, %q, %v", c.in, job, build, err)
		}
	}
	if got := buildJobPath("folder/my job"); got != "/job/folder/job/my%20job" {
		t.Errorf("buildJobPath = %q", got)
	}
}

func TestResolveBuild(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/build/lastFailedBuild/api/json", `{"number":12}`)
	ctx := context.Background()
	cases := []struct {
		sel    BuildSelector
		number int
		errHas string
	}{
		{BuildSelector{JobName: "build", BuildNumber: 5}, 5, ""},
		{BuildSelector{JobName: "build", Build: "lastFailedBuild"}, 12, ""},
		{BuildSelector{JobName: "build", Build: "LASTFAILEDBUILD"}, 12, ""},
		{BuildSelector{JobName: "build", Build: "#7"}, 7, ""},
		{BuildSelector{JobName: f.srv.URL + "/job/build/9/console"}, 9, ""},
		{BuildSelector{JobName: f.srv.URL + "/job/build/9/", BuildNumber: 3}, 3, ""},
		{BuildSelector{JobName: "build"}, 0, "missing build"},
		{BuildSelector{JobName: "build", Build: "newest"}, 0, "invalid build"},
		{BuildSelector{JobName: "build", Build: "lastSuccessfulBuild"}, 0, "has no lastSuccessfulBuild"},
	}
	for _, c := range cases {
		job, number, err := opts.resolveBuild(ctx, c.sel)
		if c.errHas != "" {
			if err == nil || !strings.Contains(err.Error(), c.errHas) {
				t.Errorf("%+v: expected error containing %q, got %v", c.sel, c.errHas, err)
			}
			continue
		}
		if err != nil || job != "build" || number != c.number {
			t.Errorf("%+v: got %q #%d, %v", c.sel, job, number, err)
		}
	}
}

func TestRunningBuildsUseURLsAndMergeExecutors(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /computer/api/json", `{"computer":[
	 {"displayName":"Built-In Node","executors":[{"idle":true}],"oneOffExecutors":[
	   {"idle":false,"progress":10,"currentExecutable":{"url":"http://x/job/all/17404/","fullDisplayName":"all all r7@branch - 17404","timestamp":1794298756592}},
	   {"idle":false,"progress":-1,"currentExecutable":{"url":"http://x/job/folder/job/waiting/3/","fullDisplayName":"folder » waiting #3","timestamp":1794298756592}}]},
	 {"displayName":"spot-1","executors":[
	   {"idle":false,"progress":53,"currentExecutable":{"url":"http://x/job/all/17404/","fullDisplayName":"all all r7@branch - 17404 (mobydick/Jenkinsfile)","timestamp":1794298756592}}]}]}`)
	builds, err := opts.getRunningBuilds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(builds) != 2 {
		t.Fatalf("expected 2 builds, got %+v", builds)
	}
	if b := builds[0]; b.JobName != "all" || b.BuildNumber != 17404 || b.Node != "spot-1" || b.Progress == nil || *b.Progress != 53 {
		t.Errorf("unexpected build: %+v", b)
	}
	// A Pipeline that is not inside a node block only holds a one-off executor.
	if b := builds[1]; b.JobName != "folder/waiting" || b.BuildNumber != 3 || b.Progress != nil {
		t.Errorf("unexpected build: %+v", b)
	}
}

func TestSearchBuildsFiltersAndCompactsParameters(t *testing.T) {
	f, opts := newFakeJenkins(t)
	var tree string
	f.handle("GET /job/build/api/json", func(w http.ResponseWriter, r *http.Request) {
		tree = r.URL.Query().Get("tree")
		fmt.Fprint(w, `{"property":[{"parameterDefinitions":[
		  {"name":"BRANCH","type":"StringParameterDefinition","defaultParameterValue":{"value":"main"}},
		  {"name":"WIPE","type":"BooleanParameterDefinition","defaultParameterValue":{"value":false}}]}],
		 "allBuilds":[
		  {"number":5,"building":true,"inProgress":true,"actions":[{"parameters":[{"name":"BRANCH","value":"feature/x"},{"name":"WIPE","value":false}]}]},
		  {"number":4,"result":"SUCCESS","displayName":"#4","actions":[{"parameters":[{"name":"BRANCH","value":"feature/x"},{"name":"WIPE","value":true},{"name":"sep","value":null}]}]},
		  {"number":3,"result":"FAILURE","actions":[{"parameters":[{"name":"BRANCH","value":"feature/x"}]}]},
		  {"number":2,"result":"SUCCESS","actions":[{"parameters":[{"name":"BRANCH","value":"main"},{"name":"WIPE","value":false}]}]},
		  {"number":1,"result":"SUCCESS","actions":[{}]}]}`)
	})
	search := func(result string, params ...string) []int {
		t.Helper()
		res, err := opts.searchBuilds(context.Background(), "build", SearchBuildsToolArgs{Result: result, Params: params, Limit: 10, MaxLookback: 250})
		if err != nil {
			t.Fatal(err)
		}
		var numbers []int
		for _, b := range res.Builds {
			numbers = append(numbers, b.Number)
		}
		return numbers
	}
	if got := fmt.Sprint(search("success", "BRANCH=feature/x")); got != "[4]" {
		t.Errorf("exact filter: %s", got)
	}
	if !strings.Contains(tree, "allBuilds[") || !strings.Contains(tree, "{0,250}") {
		t.Errorf("lookback beyond 100 needs allBuilds: tree=%q", tree)
	}
	if got := fmt.Sprint(search("", "BRANCH~=^feature/")); got != "[5 4 3]" {
		t.Errorf("regex filter: %s", got)
	}
	if got := fmt.Sprint(search("SUCCESS", "BRANCH!=feature/x")); got != "[2 1]" {
		t.Errorf("negated filter: %s", got)
	}
	if got := fmt.Sprint(search("SUCCESS", "BRANCH=")); got != "[1]" {
		t.Errorf("empty filter: %s", got)
	}
	if got := fmt.Sprint(search("BUILDING")); got != "[5]" {
		t.Errorf("building filter: %s", got)
	}
	if _, err := opts.searchBuilds(context.Background(), "build", SearchBuildsToolArgs{Params: []string{"nonsense"}, Limit: 1, MaxLookback: 1}); err == nil {
		t.Error("expected error for malformed filter")
	}

	res, _ := opts.searchBuilds(context.Background(), "build", SearchBuildsToolArgs{Result: "SUCCESS", Limit: 10, MaxLookback: 100})
	out, _ := json.Marshal(res.Builds[0])
	if want := `"nonDefaultParameters":{"BRANCH":"feature/x","WIPE":"true"}`; !strings.Contains(string(out), want) || strings.Contains(string(out), "displayName") || strings.Contains(string(out), "sep") {
		t.Errorf("unexpected build JSON: %s", out)
	}
	if out, _ := json.Marshal(res.Builds[1]); strings.Contains(string(out), "arameters") {
		t.Errorf("default-only build should list no parameters: %s", out)
	}
}

func TestGetJobsFlattensFolders(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /api/json", `{"jobs":[
	  {"name":"top","fullName":"top","color":"blue","buildable":true,"lastBuild":{"number":3,"result":"SUCCESS"}},
	  {"name":"team","fullName":"team","jobs":[{"name":"deploy","fullName":"team/deploy","color":"red","buildable":true}]}]}`)
	jobs, err := opts.getJenkinsJobs(context.Background(), "", "")
	if err != nil || len(jobs) != 3 || jobs[1].Type != "folder" || jobs[2].Name != "team/deploy" || jobs[0].LastBuild.Number != 3 {
		t.Fatalf("jobs=%+v err=%v", jobs, err)
	}
	jobs, _ = opts.getJenkinsJobs(context.Background(), "", "DEPLOY")
	if len(jobs) != 1 || jobs[0].Name != "team/deploy" {
		t.Errorf("filtered jobs=%+v", jobs)
	}
}

func TestGetBuildStagesIncludesFailedStepLog(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/pipe/7/wfapi/describe", `{"status":"FAILED","durationMillis":52000,"stages":[
	  {"id":"6","name":"checkout","status":"SUCCESS","durationMillis":2000},
	  {"id":"13","name":"build","status":"FAILED","durationMillis":49000,"error":{"message":"script returned exit code 2","type":"hudson.AbortException"}},
	  {"id":"30","name":"deploy","status":"NOT_EXECUTED","durationMillis":0}]}`)
	f.json("GET /job/pipe/7/execution/node/13/wfapi/describe", `{"id":"13","stageFlowNodes":[
	  {"id":"14","name":"Print Message","status":"SUCCESS"},
	  {"id":"15","name":"Shell Script","status":"FAILED","parameterDescription":"make all","error":{"message":"script returned exit code 2"}}]}`)
	f.json("GET /job/pipe/7/execution/node/15/wfapi/log", `{"nodeId":"15","hasMore":false,"text":"<span class=\"timestamp\"><b>08:19:19</b> </span>+ make all\n<span class=\"timestamp\"><b>08:19:20</b> </span>foo.c:1: error: expected &#039;;&#039; &lt;here&gt;\n"}`)

	stages, err := opts.getBuildStages(context.Background(), "pipe", 7, 4096, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(stages.Stages) != 3 || stages.Status != "FAILED" {
		t.Fatalf("unexpected stages: %+v", stages)
	}
	st := stages.Stages[1]
	if st.Error != "script returned exit code 2" || len(st.FailedSteps) != 1 {
		t.Fatalf("unexpected failed stage: %+v", st)
	}
	if step := st.FailedSteps[0]; step.Description != "make all" || step.Log != "+ make all\nfoo.c:1: error: expected ';' <here>\n" || step.LogTruncated {
		t.Errorf("unexpected step: %+v", step)
	}
	if n := f.count("GET /job/pipe/7/execution/node/6/wfapi/describe"); n != 0 {
		t.Error("details were fetched for a successful stage")
	}

	summary := opts.summarizeFailure(context.Background(), "pipe", 7)
	if summary == nil || len(summary.FailedStages) != 1 || summary.FailedStages[0].Name != "build" || summary.LogTail != "" {
		t.Errorf("unexpected summary: %+v", summary)
	}

	// Not a Pipeline build: explain instead of a bare 404.
	f.json("GET /job/free/1/api/json", `{"number":1,"result":"FAILURE"}`)
	if _, err := opts.getBuildStages(context.Background(), "free", 1, 100, false); err == nil || !strings.Contains(err.Error(), "not a Pipeline build") {
		t.Errorf("expected explanation, got %v", err)
	}
	if _, err := opts.getBuildStages(context.Background(), "free", 2, 100, false); err == nil || !strings.Contains(err.Error(), "build #2 not found") {
		t.Errorf("expected not-found error, got %v", err)
	}
}

func TestGetBuildDetails(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/build/7/api/json", `{"number":7,"url":"http://x/job/build/7/","building":false,"inProgress":false,"result":"SUCCESS",
	  "timestamp":1794298756592,"duration":586038,"estimatedDuration":-1,"displayName":"all r7 - 7","queueId":30617,"builtOn":"spot-1",
	  "actions":[{"causes":[{"shortDescription":"Started by user Simon"}]},{"parameters":[{"name":"TARGET","value":"all"},{"name":"WIPE","value":true}]}],
	  "changeSets":[{"items":[{"commitId":"0123456789abcdef0123","msg":"Fix thing\n\nlong body","author":{"fullName":"Dev"}}]}],
	  "artifacts":[{"relativePath":"out/report.txt"},{"relativePath":"out/app.bin"}]}`)
	b, err := opts.getBuildDetails(context.Background(), "build", 7, "REPORT")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(b)
	for _, want := range []string{
		`"displayName":"all r7 - 7"`, `"duration":"9m46s"`, `"timestamp":"2026-11-10T08:19:16Z"`, `"queueId":30617`, `"builtOn":"spot-1"`,
		`"parameters":{"TARGET":"all","WIPE":"true"}`, `"causes":["Started by user Simon"]`,
		`"changes":[{"commit":"0123456789ab","author":"Dev","message":"Fix thing"}]`, `"artifacts":["out/report.txt"]`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
	if strings.Contains(string(out), "estimatedDuration") || strings.Contains(string(out), "artifactCount") {
		t.Errorf("unknown estimate and complete artifact count should be omitted: %s", out)
	}
}

func TestDurationFormatting(t *testing.T) {
	for d, want := range map[time.Duration]string{
		112904406 * time.Nanosecond: `"113ms"`,
		586038 * time.Millisecond:   `"9m46s"`,
		0:                           `"0s"`,
	} {
		if got, _ := json.Marshal(DurationMS(d)); string(got) != want {
			t.Errorf("%v marshals to %s, want %s", d, got, want)
		}
	}
}

func TestDownloadArtifact(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.handle("GET /job/build/7/artifact/out/my report.txt", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "content") })
	dest := filepath.Join(t.TempDir(), "r.txt")
	path, size, err := opts.downloadArtifact(context.Background(), "build", 7, "out/my report.txt", dest)
	if err != nil || path != dest || size != 7 {
		t.Fatalf("path=%q size=%d err=%v", path, size, err)
	}
	if _, _, err := opts.downloadArtifact(context.Background(), "build", 7, "../../secret", dest); err == nil || !strings.Contains(err.Error(), `artifact "secret" not found`) {
		t.Errorf("expected sanitized not-found error, got %v", err)
	}
}

// connect runs the real MCP server against an in-memory client.
func connect(t *testing.T, opts *JenkinsOptions, clientOpts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverT, clientT := mcp.NewInMemoryTransports()
	ss, err := newServer(opts).Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, clientOpts).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close(); ss.Wait() })
	return cs
}

func toolText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("expected one content block, got %d", len(res.Content))
	}
	return res.Content[0].(*mcp.TextContent).Text
}

func TestServerToolsOverMCP(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.handle("GET /job/build/3/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
		writeMultipartLog(w, "[2026-11-10T08:19:16.593Z] make <all> && echo\nerror: boom\n", 0, 60, true)
	})
	f.json("GET /job/build/lastBuild/api/json", `{"number":3}`)
	cs := connect(t, opts, nil)
	ctx := context.Background()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 17 {
		t.Errorf("expected 17 tools, got %d", len(tools.Tools))
	}
	for _, tool := range tools.Tools {
		if tool.Annotations == nil || tool.Annotations.Title == "" || tool.Description == "" {
			t.Errorf("tool %s lacks annotations or description", tool.Name)
		}
		mutating := map[string]bool{"jenkins_start_job": true, "jenkins_stop_build": true, "jenkins_download_build_log": true, "jenkins_download_artifact": true}
		if tool.Annotations != nil && tool.Annotations.ReadOnlyHint == mutating[tool.Name] {
			t.Errorf("tool %s has wrong readOnlyHint", tool.Name)
		}
	}

	// Schema defaults apply, selector fields of the embedded struct are accepted.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_get_build_logs", Arguments: map[string]any{"job_name": "build", "build": "lastBuild"}})
	if err != nil || res.IsError {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	text := toolText(t, res)
	if !strings.Contains(text, `"logs":"make <all> && echo\nerror: boom\n"`) || !strings.Contains(text, `"buildNumber":3`) || !strings.Contains(text, `"nextOffset":58`) {
		t.Errorf("unexpected result (HTML escaping or wrong content): %s", text)
	}

	// output=text returns the bare log, nothing else.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_download_build_log", Arguments: map[string]any{"job_name": "build", "build_number": 3, "output": "text"}})
	if err != nil || res.IsError || res.StructuredContent != nil {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if got := toolText(t, res); got != "[2026-11-10T08:19:16.593Z] make <all> && echo\nerror: boom\n" {
		t.Errorf("unexpected raw log %q", got)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_download_build_log", Arguments: map[string]any{"job_name": "build", "build_number": 3}})
	if err != nil || res.IsError {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	var dl DownloadBuildLogToolResponse
	if err := json.Unmarshal([]byte(toolText(t, res)), &dl); err != nil || dl.Lines != 2 {
		t.Fatalf("dl=%+v err=%v", dl, err)
	}
	if data, err := os.ReadFile(dl.Path); err != nil || !strings.HasSuffix(string(data), "error: boom\n") {
		t.Errorf("downloaded file: %q %v", data, err)
	}

	// Tool errors are reported as tool results, readable for the model.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_get_build_logs", Arguments: map[string]any{"job_name": "build"}})
	if err != nil || !res.IsError || !strings.Contains(toolText(t, res), "missing build") {
		t.Errorf("res=%+v err=%v", res, err)
	}
}

func TestWaitSendsProgressNotifications(t *testing.T) {
	f, opts := newFakeJenkins(t)
	var polls atomic.Int32
	f.handle("GET /job/build/4/api/json", func(w http.ResponseWriter, r *http.Request) {
		if polls.Add(1) < 3 {
			fmt.Fprint(w, `{"number":4,"building":true,"inProgress":true,"timestamp":1}`)
			return
		}
		fmt.Fprint(w, `{"number":4,"building":false,"inProgress":false,"result":"SUCCESS"}`)
	})
	var notified atomic.Int32
	cs := connect(t, opts, &mcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, req *mcp.ProgressNotificationClientRequest) {
			if strings.Contains(req.Params.Message, "build #4 running") {
				notified.Add(1)
			}
		},
	})
	params := &mcp.CallToolParams{Name: "jenkins_wait_for_running_build", Arguments: map[string]any{"job_name": "build", "build_number": 4}}
	params.SetProgressToken("tok")
	res, err := cs.CallTool(context.Background(), params)
	if err != nil || res.IsError || !strings.Contains(toolText(t, res), `"status":"success"`) {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if notified.Load() == 0 {
		t.Error("no progress notification received")
	}
}
