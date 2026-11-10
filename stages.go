package main

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"regexp"
	"strings"
)

// Stage is a Pipeline stage as reported by the Pipeline Stage View REST API.
type Stage struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Status      string      `json:"status"` // SUCCESS, FAILED, ABORTED, UNSTABLE, IN_PROGRESS, NOT_EXECUTED, ...
	Duration    DurationMS  `json:"duration"`
	Error       string      `json:"error,omitempty"`
	FailedSteps []StageStep `json:"failedSteps,omitempty"`
}

// StageStep is a failed step inside a stage.
type StageStep struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"` // step arguments, e.g. the shell script
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	Log          string `json:"log,omitempty"` // end of the step's own log output
	LogTruncated bool   `json:"logTruncated,omitempty"`
}

// BuildStages is the result payload for jenkins_get_build_stages.
type BuildStages struct {
	JobName     string     `json:"jobName"`
	BuildNumber int        `json:"buildNumber"`
	Status      string     `json:"status"`
	Duration    DurationMS `json:"duration"`
	Stages      []Stage    `json:"stages"`
}

// FailureSummary condenses why a build did not succeed.
type FailureSummary struct {
	FailedStages []Stage    `json:"failedStages,omitempty"`
	ErrorLines   []LogMatch `json:"errorLines,omitempty"` // last lines matching the default error pattern
	LogTail      string     `json:"logTail,omitempty"`
}

type wfError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

func (e *wfError) String() string {
	if e == nil {
		return ""
	}
	return truncate(strings.TrimSpace(e.Message), 500)
}

type wfNode struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Status               string   `json:"status"`
	ParameterDescription string   `json:"parameterDescription"`
	DurationMillis       int64    `json:"durationMillis"`
	Error                *wfError `json:"error"`
	Stages               []wfNode `json:"stages"`
	StageFlowNodes       []wfNode `json:"stageFlowNodes"`
}

const maxFailedStepsPerStage = 3

func isFailedStatus(status string) bool {
	switch status {
	case "FAILED", "ABORTED", "UNSTABLE":
		return true
	}
	return false
}

var (
	wfTimestampRe = regexp.MustCompile(`(?s)<span class="timestamp">.*?</span>`)
	wfTagRe       = regexp.MustCompile(`(?s)<[^>]*>`)
)

// htmlLogToText converts the HTML console fragment returned by the stage view
// log API into cleaned plain text.
func htmlLogToText(s string) string {
	s = wfTimestampRe.ReplaceAllString(s, "")
	s = html.UnescapeString(wfTagRe.ReplaceAllString(s, ""))
	var buf bytes.Buffer
	_ = cleanLog(&buf, strings.NewReader(s))
	return buf.String()
}

// getBuildStages returns the Pipeline stages of a build. For stages that did
// not succeed, the failing steps are included with their error and the end of
// their log (up to maxStepLog bytes each).
func (opts *JenkinsOptions) getBuildStages(ctx context.Context, jobName string, buildNumber int, maxStepLog int, onlyFailed bool) (*BuildStages, error) {
	stages, err := opts.fetchBuildStages(ctx, jobName, buildNumber, maxStepLog, onlyFailed)
	if isNotFound(err) {
		// Tell a missing build apart from a build without stage information.
		if _, berr := opts.getBuild(ctx, jobName, buildNumber); berr != nil {
			return nil, berr
		}
		return nil, fmt.Errorf("no stage information for job %q build #%d: not a Pipeline build, or the Pipeline Stage View plugin is not installed; use jenkins_grep_build_log instead", jobName, buildNumber)
	}
	return stages, err
}

func (opts *JenkinsOptions) fetchBuildStages(ctx context.Context, jobName string, buildNumber int, maxStepLog int, onlyFailed bool) (*BuildStages, error) {
	base := fmt.Sprintf("%s/%d", buildJobPath(jobName), buildNumber)
	var run wfNode
	if err := opts.getJSON(ctx, base+"/wfapi/describe", &run); err != nil {
		return nil, err
	}

	res := &BuildStages{JobName: jobName, BuildNumber: buildNumber, Status: run.Status, Duration: msDuration(run.DurationMillis), Stages: []Stage{}}
	for _, st := range run.Stages {
		failed := isFailedStatus(st.Status)
		if onlyFailed && !failed {
			continue
		}
		stage := Stage{ID: st.ID, Name: st.Name, Status: st.Status, Duration: msDuration(st.DurationMillis), Error: st.Error.String()}
		if failed {
			stage.FailedSteps = opts.getFailedSteps(ctx, base, st.ID, maxStepLog)
		}
		res.Stages = append(res.Stages, stage)
	}
	return res, nil
}

// getFailedSteps loads the failed steps of a stage with their log tails.
// Errors are ignored: the stage overview is still useful without step details.
func (opts *JenkinsOptions) getFailedSteps(ctx context.Context, base, stageID string, maxStepLog int) []StageStep {
	var detail wfNode
	if err := opts.getJSON(ctx, fmt.Sprintf("%s/execution/node/%s/wfapi/describe", base, stageID), &detail); err != nil {
		return nil
	}
	var failed []wfNode
	for _, n := range detail.StageFlowNodes {
		if isFailedStatus(n.Status) {
			failed = append(failed, n)
		}
	}
	// The last failed steps are the ones that ended the stage.
	if len(failed) > maxFailedStepsPerStage {
		failed = failed[len(failed)-maxFailedStepsPerStage:]
	}
	var steps []StageStep
	for _, n := range failed {
		step := StageStep{ID: n.ID, Name: n.Name, Description: truncate(n.ParameterDescription, 300), Status: n.Status, Error: n.Error.String()}
		var logData struct {
			Text    string `json:"text"`
			HasMore bool   `json:"hasMore"`
		}
		if err := opts.getJSON(ctx, fmt.Sprintf("%s/execution/node/%s/wfapi/log", base, n.ID), &logData); err == nil && maxStepLog > 0 {
			text := []byte(htmlLogToText(logData.Text))
			tail := tailLines(text, maxStepLog, 0, false)
			step.Log = tail.text
			step.LogTruncated = logData.HasMore || tail.offset > 0
		}
		steps = append(steps, step)
	}
	return steps
}

// summarizeFailure gathers the most useful hints about a failed build: the
// failed Pipeline stages and steps when available, otherwise matching error
// lines and the end of the log. It is best effort and never fails.
func (opts *JenkinsOptions) summarizeFailure(ctx context.Context, jobName string, buildNumber int) *FailureSummary {
	summary := &FailureSummary{}
	haveStepLogs := false
	if stages, err := opts.fetchBuildStages(ctx, jobName, buildNumber, 3000, true); err == nil {
		summary.FailedStages = stages.Stages
		for _, st := range stages.Stages {
			for _, step := range st.FailedSteps {
				haveStepLogs = haveStepLogs || step.Log != ""
			}
		}
	}
	if !haveStepLogs {
		if snap, err := opts.getLog(ctx, jobName, buildNumber); err == nil {
			summary.ErrorLines, _, _ = grepLog(snap.Data, grepOptions{pattern: defaultErrorRe, exclude: defaultNoiseRe, maxMatches: 8, tail: true})
			summary.LogTail = tailLines(snap.Data, 2000, 20, false).text
		}
	}
	if len(summary.FailedStages) == 0 && len(summary.ErrorLines) == 0 && summary.LogTail == "" {
		return nil
	}
	return summary
}

var (
	defaultErrorRe = regexp.MustCompile(defaultErrorPattern)
	// defaultNoiseRe drops Jenkins' own closing line from default error searches.
	defaultNoiseRe = regexp.MustCompile(`^Finished: [A-Z_]+$`)
)
