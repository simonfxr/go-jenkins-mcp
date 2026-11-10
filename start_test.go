package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeJenkins is a scriptable Jenkins stand-in. Handlers are looked up by
// "METHOD path" and may be replaced while a test runs.
type fakeJenkins struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	calls    []string
}

func newFakeJenkins(t *testing.T) (*fakeJenkins, *JenkinsOptions) {
	t.Helper()
	f := &fakeJenkins{t: t, handlers: map[string]http.HandlerFunc{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		f.mu.Lock()
		f.calls = append(f.calls, key)
		h := f.handlers[key]
		f.mu.Unlock()
		if user, pass, ok := r.BasicAuth(); !ok || user != "user" || pass != "token" {
			t.Errorf("request %s without expected basic auth", key)
		}
		if h == nil {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)

	opts := &JenkinsOptions{URL: f.srv.URL, User: "user", Token: "token", PollInterval: 5 * time.Millisecond, RetryBackoff: time.Millisecond}
	opts.init(t.TempDir(), "")
	return f, opts
}

func (f *fakeJenkins) handle(key string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[key] = h
}

// json registers a static JSON response.
func (f *fakeJenkins) json(key, body string) {
	f.handle(key, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	})
}

func (f *fakeJenkins) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == key {
			n++
		}
	}
	return n
}

const paramJobJSON = `{"fullName":"build","buildable":true,"property":[{},{"parameterDefinitions":[
 {"name":"BRANCH","type":"StringParameterDefinition","defaultParameterValue":{"value":"main"}},
 {"name":"TARGET","type":"ChoiceParameterDefinition","defaultParameterValue":{"value":"all"},"choices":["all","arm"]},
 {"name":"WIPE","type":"BooleanParameterDefinition","defaultParameterValue":{"value":false}},
 {"name":"sep","type":"ParameterSeparatorDefinition"}]}]}`

func noProgress(string) {}

func TestStartJobQueuedAndStarted(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/build/api/json", paramJobJSON)
	var form url.Values
	f.handle("POST /job/build/buildWithParameters", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		w.Header().Set("Location", f.srv.URL+"/queue/item/42/")
		w.WriteHeader(http.StatusCreated)
	})
	polls := 0
	f.handle("GET /queue/item/42/api/json", func(w http.ResponseWriter, r *http.Request) {
		polls++
		if polls < 3 {
			fmt.Fprint(w, `{"id":42,"task":{"name":"build","url":"http://x/job/build/"},"why":"Waiting for next available executor"}`)
			return
		}
		fmt.Fprint(w, `{"id":42,"task":{"name":"build","url":"http://x/job/build/"},"executable":{"number":7,"url":"http://x/job/build/7/","building":true}}`)
	})

	res, err := opts.startJob(context.Background(), StartJobToolArgs{
		JobName:    f.srv.URL + "/job/build/",
		Parameters: map[string]any{"BRANCH": "feature/x", "WIPE": true},
	}, noProgress)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "started" || res.BuildNumber != 7 || res.QueueID != 42 || res.AlreadyQueued || res.JobName != "build" {
		t.Errorf("unexpected result: %+v", res)
	}
	if form.Get("BRANCH") != "feature/x" || form.Get("WIPE") != "true" || form.Has("TARGET") {
		t.Errorf("unexpected form: %v", form)
	}
}

func TestStartJobAlreadyQueuedIsNotAnError(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/build/api/json", paramJobJSON)
	f.handle("POST /job/build/buildWithParameters", func(w http.ResponseWriter, r *http.Request) {
		// Jenkins folds identical requests into the existing queue item.
		w.Header().Set("Location", "/queue/item/42/")
		w.WriteHeader(http.StatusSeeOther)
	})
	res, err := opts.startJob(context.Background(), StartJobToolArgs{JobName: "build", Wait: "none"}, noProgress)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AlreadyQueued || res.Status != "queued" || res.QueueID != 42 {
		t.Errorf("unexpected result: %+v", res)
	}
	if n := f.count("GET /queue/item/42/"); n != 0 {
		t.Errorf("redirect to the queue item page was followed %d times", n)
	}
}

func TestStartJobRefusedByQueue(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/build/api/json", paramJobJSON)
	f.handle("POST /job/build/buildWithParameters", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ".", http.StatusFound)
	})
	_, err := opts.startJob(context.Background(), StartJobToolArgs{JobName: "build"}, noProgress)
	if err == nil || !strings.Contains(err.Error(), "did not report a queue item") {
		t.Errorf("expected refusal error, got %v", err)
	}
}

func TestStartJobValidatesParameters(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/build/api/json", paramJobJSON)
	cases := []struct {
		params map[string]any
		want   string
	}{
		{map[string]any{"BRANCHH": "x"}, `unknown parameter "BRANCHH"`},
		{map[string]any{"branch": "x"}, `did you mean "BRANCH"`},
		{map[string]any{"TARGET": "x86"}, "valid choices: all, arm"},
		{map[string]any{"WIPE": "maybe"}, "use true or false"},
		{map[string]any{"BRANCH": []any{"a"}}, "must be a string, number or boolean"},
		{map[string]any{"sep": "x"}, `unknown parameter "sep"`},
	}
	for _, c := range cases {
		_, err := opts.startJob(context.Background(), StartJobToolArgs{JobName: "build", Parameters: c.params}, noProgress)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("params %v: expected error containing %q, got %v", c.params, c.want, err)
		}
	}
	if n := f.count("POST /job/build/buildWithParameters"); n != 0 {
		t.Errorf("build was triggered %d times despite invalid parameters", n)
	}
}

func TestStartJobNotParameterizedUsesBuild(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/plain/api/json", `{"fullName":"plain","buildable":true,"property":[{}]}`)
	f.handle("POST /job/plain/build", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/queue/item/5/")
		w.WriteHeader(http.StatusCreated)
	})
	res, err := opts.startJob(context.Background(), StartJobToolArgs{JobName: "plain", Wait: "none"}, noProgress)
	if err != nil || res.QueueID != 5 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if _, err := opts.startJob(context.Background(), StartJobToolArgs{JobName: "plain", Parameters: map[string]any{"A": "b"}}, noProgress); err == nil || !strings.Contains(err.Error(), "not parameterized") {
		t.Errorf("expected not-parameterized error, got %v", err)
	}
	if _, err := opts.startJob(context.Background(), StartJobToolArgs{JobName: "missing"}, noProgress); err == nil || !strings.Contains(err.Error(), `job "missing" not found`) {
		t.Errorf("expected not-found error, got %v", err)
	}
}

func TestStartJobFromBuildAndWaitCompleted(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/build/api/json", paramJobJSON)
	// TARGET=x86 is no longer a valid choice and must be dropped; GONE no longer exists.
	f.json("GET /job/build/3/api/json", `{"number":3,"building":false,"result":"FAILURE","actions":[{"parameters":[
		{"name":"BRANCH","value":"old"},{"name":"TARGET","value":"x86"},{"name":"WIPE","value":true},{"name":"GONE","value":"1"},{"name":"sep","value":null}]}]}`)
	var form url.Values
	f.handle("POST /job/build/buildWithParameters", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		w.Header().Set("Location", "/queue/item/9/")
		w.WriteHeader(http.StatusCreated)
	})
	f.json("GET /queue/item/9/api/json", `{"id":9,"task":{"url":"http://x/job/build/"},"executable":{"number":4,"url":"http://x/job/build/4/","building":true}}`)
	polls := 0
	f.handle("GET /job/build/4/api/json", func(w http.ResponseWriter, r *http.Request) {
		polls++
		if polls < 3 {
			fmt.Fprint(w, `{"number":4,"building":true,"inProgress":true,"timestamp":1}`)
			return
		}
		fmt.Fprint(w, `{"number":4,"building":false,"inProgress":false,"result":"SUCCESS","duration":65000}`)
	})

	res, err := opts.startJob(context.Background(), StartJobToolArgs{
		JobName: "build", FromBuild: 3, Parameters: map[string]any{"BRANCH": "new"}, Wait: "completed",
	}, noProgress)
	if err != nil {
		t.Fatal(err)
	}
	if got := form.Encode(); got != "BRANCH=new&WIPE=true" {
		t.Errorf("unexpected form %q", got)
	}
	if res.Status != "completed" || res.Result != "SUCCESS" || res.BuildNumber != 4 || res.Failure != nil {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestWaitForBuildMissingBuildFailsFast(t *testing.T) {
	_, opts := newFakeJenkins(t)
	start := time.Now()
	_, err := opts.waitForBuild(context.Background(), "nope", 1, time.Minute, noProgress)
	if err == nil || !strings.Contains(err.Error(), `job "nope" build #1 not found`) {
		t.Fatalf("expected not-found error, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("missing build was not reported promptly")
	}
}

func TestWaitForBuildTimeoutReportsRunning(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/build/4/api/json", `{"number":4,"building":true,"inProgress":true,"estimatedDuration":60000}`)
	res, err := opts.waitForBuild(context.Background(), "build", 4, 20*time.Millisecond, noProgress)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "running" || !res.TimedOut || res.Failure != nil {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestWaitForBuildWaitsForPostProductionAndSummarizesFailure(t *testing.T) {
	f, opts := newFakeJenkins(t)
	polls := 0
	f.handle("GET /job/build/4/api/json", func(w http.ResponseWriter, r *http.Request) {
		polls++
		switch {
		case polls == 1:
			// building=false but still in post-production: not finished yet.
			fmt.Fprint(w, `{"number":4,"building":false,"inProgress":true,"result":"FAILURE"}`)
		case polls == 2:
			http.Error(w, "boom", http.StatusInternalServerError) // transient
		default:
			fmt.Fprint(w, `{"number":4,"building":false,"inProgress":false,"result":"FAILURE","duration":1000}`)
		}
	})
	f.handle("GET /job/build/4/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
		writeMultipartLog(w, "compiling\nfoo.c:1: error: boom\ncleanup\nFinished: FAILURE\n", 0, 100, true)
	})
	res, err := opts.waitForBuild(context.Background(), "build", 4, time.Minute, noProgress)
	if err != nil {
		t.Fatal(err)
	}
	if polls != 3 || res.Status != "failure" || res.TimedOut {
		t.Errorf("polls=%d result=%+v", polls, res)
	}
	// No stage API on this fake: falls back to error lines and log tail.
	if res.Failure == nil || len(res.Failure.ErrorLines) != 1 || res.Failure.ErrorLines[0].Line != 2 || !strings.Contains(res.Failure.LogTail, "Finished: FAILURE") {
		t.Errorf("unexpected failure summary: %+v", res.Failure)
	}
}

func TestQueueItemFallsBackToBuildQueueID(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/build/api/json", `{"url":"http://x/job/build/","allBuilds":[{"number":9,"queueId":50},{"number":8,"queueId":42,"building":true}]}`)

	item, err := opts.getQueueItem(context.Background(), 42, "build")
	if err != nil {
		t.Fatal(err)
	}
	if item.Status != "started" || item.Build == nil || item.Build.Number != 8 {
		t.Errorf("unexpected item: %+v", item)
	}
	if _, err := opts.getQueueItem(context.Background(), 42, ""); err == nil || !strings.Contains(err.Error(), "pass job_name") {
		t.Errorf("expected hint to pass job_name, got %v", err)
	}
	// A vanished item must not make waiting run into its timeout.
	start := time.Now()
	if _, err := opts.waitForQueueItem(context.Background(), 77, "build", time.Minute, noProgress); err == nil {
		t.Error("expected error for unknown queue item")
	}
	if time.Since(start) > 5*time.Second {
		t.Error("unknown queue item was not reported promptly")
	}
}

func TestStopBuild(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /job/build/1/api/json", `{"number":1,"building":false,"inProgress":false,"result":"SUCCESS"}`)
	res, err := opts.stopBuild(context.Background(), "build", 1)
	if err != nil || res.Status != "not_running" || res.Result != "SUCCESS" {
		t.Errorf("res=%+v err=%v", res, err)
	}
	if f.count("POST /job/build/1/stop") != 0 {
		t.Error("stop was posted for a finished build")
	}

	stopped := false
	f.handle("GET /job/build/2/api/json", func(w http.ResponseWriter, r *http.Request) {
		if stopped {
			fmt.Fprint(w, `{"number":2,"building":false,"inProgress":false,"result":"ABORTED"}`)
			return
		}
		fmt.Fprint(w, `{"number":2,"building":true,"inProgress":true}`)
	})
	f.handle("POST /job/build/2/stop", func(w http.ResponseWriter, r *http.Request) {
		stopped = true
		http.Redirect(w, r, "/job/build/2/", http.StatusFound)
	})
	res, err = opts.stopBuild(context.Background(), "build", 2)
	if err != nil || res.Status != "stopped" || res.Result != "ABORTED" {
		t.Errorf("res=%+v err=%v", res, err)
	}
}

func TestStopQueuedCancelsQueueItem(t *testing.T) {
	f, opts := newFakeJenkins(t)
	cancelled := false
	f.handle("GET /queue/item/42/api/json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":42,"task":{"url":"http://x/job/a/job/b/"},"why":"waiting","cancelled":%t}`, cancelled)
	})
	f.handle("POST /queue/cancelItem", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "42" {
			t.Errorf("unexpected id %q", r.URL.RawQuery)
		}
		cancelled = true
		w.WriteHeader(http.StatusNoContent)
	})
	res, err := opts.stopQueued(context.Background(), 42, "")
	if err != nil || res.Status != "cancelled_in_queue" || res.JobName != "a/b" {
		t.Errorf("res=%+v err=%v", res, err)
	}
}

func TestPostFetchesCrumbOnlyWhenRejected(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.json("GET /crumbIssuer/api/json", `{"crumbRequestField":"Jenkins-Crumb","crumb":"abc"}`)
	f.handle("POST /needs-crumb", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Jenkins-Crumb") != "abc" {
			http.Error(w, "No valid crumb was included in the request", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	f.handle("POST /no-crumb", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusCreated) })

	resp, err := opts.post(context.Background(), "/no-crumb", nil)
	if err != nil || resp.StatusCode != http.StatusCreated || f.count("GET /crumbIssuer/api/json") != 0 {
		t.Fatalf("token-style post: err=%v crumbs=%d", err, f.count("GET /crumbIssuer/api/json"))
	}
	resp.Body.Close()
	resp, err = opts.post(context.Background(), "/needs-crumb", nil)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("crumb retry failed: %v %v", resp, err)
	}
	resp.Body.Close()
}

func TestGetRetriesTransientGatewayErrors(t *testing.T) {
	f, opts := newFakeJenkins(t)
	n := 0
	f.handle("GET /job/build/1/api/json", func(w http.ResponseWriter, r *http.Request) {
		n++
		if n < 3 {
			http.Error(w, "<html><head><title>502 Bad Gateway</title></head><body><h1>Bad Gateway</h1></body></html>", http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, `{"number":1,"result":"SUCCESS"}`)
	})
	b, err := opts.getBuild(context.Background(), "build", 1)
	if err != nil || b.Result != "SUCCESS" || n != 3 {
		t.Errorf("build=%+v err=%v attempts=%d", b, err, n)
	}
}

func TestErrorBodiesAreSummarized(t *testing.T) {
	page := "<!DOCTYPE html><html><head><title>Oops</title><script>var x = '<b>';</script><style>p{}</style></head><body><h1>Error</h1><p>Illegal choice for parameter TARGET: x86</p>" + strings.Repeat("<div>filler</div>", 500) + "</body></html>"
	got := summarizeErrorBody([]byte(page))
	if !strings.HasPrefix(got, "Error Illegal choice for parameter TARGET: x86") || len(got) > 310 || strings.Contains(got, "<") {
		t.Errorf("unexpected summary %q", got)
	}
	if got := summarizeErrorBody([]byte("  plain\n message ")); got != "plain message" {
		t.Errorf("unexpected plain summary %q", got)
	}
}
