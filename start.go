package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxPollFailures is the number of consecutive failed polls tolerated while waiting.
const maxPollFailures = 5

// jobStartInfo is what is needed to validate and trigger a build.
type jobStartInfo struct {
	Name          string
	Buildable     bool
	Parameterized bool
	Params        []BuildParameter
}

func (opts *JenkinsOptions) getJobStartInfo(ctx context.Context, jobName string) (*jobStartInfo, error) {
	var data struct {
		FullName  string        `json:"fullName"`
		Buildable bool          `json:"buildable"`
		Property  paramDefsWire `json:"property"`
	}
	if err := opts.getJSON(ctx, buildJobPath(jobName)+"/api/json?tree=fullName,buildable,"+paramDefTree, &data); err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("job %q not found", jobName)
		}
		return nil, err
	}
	info := &jobStartInfo{Name: firstNonEmpty(data.FullName, jobName), Buildable: data.Buildable}
	info.Params, info.Parameterized = data.Property.definitions()
	return info, nil
}

// buildStartParams validates the requested parameters against the job's
// definitions. Jenkins silently ignores unknown parameter names and answers
// invalid choices with an HTML error page, so both are rejected up front.
// base holds parameters copied from a previous build; they are applied
// leniently (dropped when no longer valid), while params are strict.
func buildStartParams(info *jobStartInfo, base map[string]string, params map[string]any) (map[string]string, error) {
	defs := make(map[string]BuildParameter, len(info.Params))
	names := make([]string, 0, len(info.Params))
	for _, d := range info.Params {
		defs[d.Name] = d
		names = append(names, d.Name)
	}
	if !info.Parameterized && len(params) > 0 {
		return nil, fmt.Errorf("job %q is not parameterized but parameters were given", info.Name)
	}

	out := map[string]string{}
	for name, value := range base {
		d, ok := defs[name]
		if !ok || strings.Contains(d.Type, "Password") {
			continue
		}
		if v, err := checkParamValue(d, value); err == nil {
			out[name] = v
		}
	}

	keys := make([]string, 0, len(params))
	for name := range params {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		d, ok := defs[name]
		if !ok {
			hint := ""
			for _, n := range names {
				if strings.EqualFold(n, name) {
					hint = fmt.Sprintf(" (did you mean %q?)", n)
				}
			}
			return nil, fmt.Errorf("unknown parameter %q for job %q%s; valid parameters: %s", name, info.Name, hint, strings.Join(names, ", "))
		}
		var s string
		switch x := params[name].(type) {
		case nil:
			delete(out, name) // use the job default
			continue
		case string, bool, float64, int, int64:
			s = formatParamValue(x)
		default:
			return nil, fmt.Errorf("parameter %q must be a string, number or boolean", name)
		}
		v, err := checkParamValue(d, s)
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

// checkParamValue validates a value against a choice or boolean definition.
func checkParamValue(d BuildParameter, value string) (string, error) {
	switch {
	case len(d.Choices) > 0:
		for _, c := range d.Choices {
			if c == value {
				return value, nil
			}
		}
		return "", fmt.Errorf("invalid value %q for parameter %q; valid choices: %s", value, d.Name, strings.Join(d.Choices, ", "))
	case strings.Contains(d.Type, "Boolean"):
		b, err := strconv.ParseBool(strings.ToLower(value))
		if err != nil {
			return "", fmt.Errorf("invalid value %q for boolean parameter %q; use true or false", value, d.Name)
		}
		return strconv.FormatBool(b), nil
	}
	return value, nil
}

// startJob validates parameters, triggers a build and optionally waits for it
// to leave the queue or to complete.
func (opts *JenkinsOptions) startJob(ctx context.Context, args StartJobToolArgs, progress progressFunc) (*StartJobToolResponse, error) {
	jobName, _, err := parseJobRef(args.JobName)
	if err != nil {
		return nil, err
	}
	wait := strings.ToLower(strings.TrimSpace(args.Wait))
	switch wait {
	case "":
		wait = "started"
	case "none", "started", "completed":
	default:
		return nil, fmt.Errorf("invalid wait %q: expected none, started or completed", args.Wait)
	}
	timeout := time.Duration(args.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
		if wait == "completed" {
			timeout = 10 * time.Minute
		}
	}

	info, err := opts.getJobStartInfo(ctx, jobName)
	if err != nil {
		return nil, err
	}
	if !info.Buildable {
		return nil, fmt.Errorf("job %q is not buildable (disabled, or a folder)", jobName)
	}
	var base map[string]string
	if args.FromBuild > 0 {
		prev, err := opts.getBuild(ctx, jobName, args.FromBuild)
		if err != nil {
			return nil, fmt.Errorf("from_build: %w", err)
		}
		base = prev.Parameters
	}
	params, err := buildStartParams(info, base, args.Parameters)
	if err != nil {
		return nil, err
	}

	// buildWithParameters only exists for parameterized jobs; plain jobs use build.
	apiPath := buildJobPath(jobName) + "/build"
	var form url.Values
	if info.Parameterized {
		apiPath = buildJobPath(jobName) + "/buildWithParameters"
		form = url.Values{}
		for k, v := range params {
			form.Set(k, v)
		}
	}
	resp, err := opts.post(ctx, apiPath, form)
	if err != nil {
		return nil, fmt.Errorf("failed to start build (it is unknown whether Jenkins received the request; check jenkins_get_job before retrying): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("failed to start build: %w", newAPIError(resp))
	}

	// 201 + queue item: scheduled. 303 + queue item: an identical build was
	// already queued and Jenkins folded this request into it. Any other
	// redirect means the queue refused the build.
	result := &StartJobToolResponse{JobName: jobName, Status: "queued", Parameters: params}
	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "/queue/item/") {
		result.QueueID = extractQueueID(loc)
	}
	if result.QueueID == 0 {
		return nil, fmt.Errorf("jenkins did not report a queue item for job %q (HTTP %d); the queue most likely refused the build, check jenkins_get_job before retrying", jobName, resp.StatusCode)
	}
	result.AlreadyQueued = resp.StatusCode == http.StatusSeeOther
	if wait == "none" {
		return result, nil
	}

	start := time.Now()
	qres, err := opts.waitForQueueItem(ctx, result.QueueID, jobName, timeout, progress)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// The build is scheduled; report that rather than failing the call.
		result.Note = "build was queued but its queue state could not be read: " + err.Error()
		return result, nil
	}
	result.Status = qres.Status
	result.TimedOut = qres.TimedOut
	if qres.QueueItem != nil {
		result.Why = qres.QueueItem.Why
	}
	if qres.Build == nil {
		return result, nil
	}
	result.BuildNumber = qres.Build.Number
	result.BuildURL = qres.Build.URL
	if wait != "completed" {
		return result, nil
	}

	bres, err := opts.waitForBuild(ctx, jobName, result.BuildNumber, max(timeout-time.Since(start), 0), progress)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		result.Note = "build started but waiting for it failed: " + err.Error()
		return result, nil
	}
	result.TimedOut = bres.TimedOut
	result.Duration = bres.Duration
	if !bres.TimedOut {
		result.Status = "completed"
		result.Result = bres.Result
		result.Failure = bres.Failure
	}
	return result, nil
}

// stopBuild aborts a running build and reports what actually happened.
func (opts *JenkinsOptions) stopBuild(ctx context.Context, jobName string, buildNumber int) (*StopBuildToolResponse, error) {
	res := &StopBuildToolResponse{JobName: jobName, BuildNumber: buildNumber}
	build, err := opts.getBuild(ctx, jobName, buildNumber)
	if err != nil {
		return nil, err
	}
	if !build.inProgress {
		res.Status = "not_running"
		res.Result = build.Result
		return res, nil
	}

	resp, err := opts.post(ctx, fmt.Sprintf("%s/%d/stop", buildJobPath(jobName), buildNumber), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to stop build: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("failed to stop build: %w", newAPIError(resp))
	}

	// Aborting is asynchronous (Pipelines unwind their steps); give it a moment.
	res.Status = "stopping"
	deadline := time.Now().Add(5 * opts.PollInterval)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return res, nil
		case <-time.After(min(opts.PollInterval, time.Second)):
		}
		if b, err := opts.getBuild(ctx, jobName, buildNumber); err == nil && !b.inProgress {
			res.Status = "stopped"
			res.Result = b.Result
			break
		}
	}
	return res, nil
}

// stopQueued cancels a queued build, or stops the build it already turned into.
func (opts *JenkinsOptions) stopQueued(ctx context.Context, queueID int, jobName string) (*StopBuildToolResponse, error) {
	item, err := opts.getQueueItem(ctx, queueID, jobName)
	if err != nil {
		return nil, err
	}
	cancelled := item.Status == "cancelled"
	if item.Status == "queued" {
		if cancelled, err = opts.cancelQueueItem(ctx, queueID); err != nil {
			return nil, err
		}
		// The item may have turned into a build in the meantime.
		if again, err := opts.getQueueItem(ctx, queueID, firstNonEmpty(jobName, item.JobName)); err == nil {
			item = again
			cancelled = cancelled || item.Status == "cancelled"
		}
	}
	switch {
	case item.Status == "started":
		res, err := opts.stopBuild(ctx, item.JobName, item.Build.Number)
		if err != nil {
			return nil, err
		}
		res.QueueID = queueID
		return res, nil
	case cancelled:
		return &StopBuildToolResponse{JobName: item.JobName, QueueID: queueID, Status: "cancelled_in_queue"}, nil
	}
	return nil, fmt.Errorf("queue item #%d could not be cancelled (still queued: %s)", queueID, item.Why)
}

// waitForBuild polls a build until it finished or the timeout expired.
// A missing build is reported immediately; transient errors are tolerated.
func (opts *JenkinsOptions) waitForBuild(ctx context.Context, jobName string, buildNumber int, timeout time.Duration, progress progressFunc) (*WaitForRunningBuildToolResponse, error) {
	start := time.Now()
	deadline := start.Add(timeout)
	failures := 0
	var last *Build
	for {
		build, err := opts.getBuild(ctx, jobName, buildNumber)
		switch {
		case err == nil:
			failures = 0
			last = build
			if !build.inProgress {
				res := newWaitResponse(jobName, build, start)
				res.Status = strings.ToLower(build.Result)
				if res.Status == "" {
					res.Status = "unknown"
				}
				if build.Result != "SUCCESS" {
					res.Failure = opts.summarizeFailure(ctx, jobName, buildNumber)
				}
				return res, nil
			}
			msg := fmt.Sprintf("%s #%d running for %s", jobName, buildNumber, time.Duration(build.Duration).Round(time.Second))
			if build.EstimatedDuration > 0 {
				msg += fmt.Sprintf(" (estimated %s)", time.Duration(build.EstimatedDuration).Round(time.Second))
			}
			progress(msg)
		case ctx.Err() != nil:
			return nil, ctx.Err()
		default:
			failures++
			if last == nil || failures >= maxPollFailures {
				return nil, err
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			res := newWaitResponse(jobName, last, start)
			res.Status = "running"
			res.TimedOut = true
			return res, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(min(opts.PollInterval, remaining)):
		}
	}
}

func newWaitResponse(jobName string, build *Build, start time.Time) *WaitForRunningBuildToolResponse {
	return &WaitForRunningBuildToolResponse{
		JobName:           jobName,
		BuildNumber:       build.Number,
		URL:               build.URL,
		Result:            build.Result,
		Duration:          build.Duration,
		EstimatedDuration: build.EstimatedDuration,
		WaitTime:          DurationMS(time.Since(start)),
	}
}
