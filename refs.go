package main

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// BuildSelector identifies a build in tool arguments.
type BuildSelector struct {
	JobName     string `json:"job_name" jsonschema:"Job name or folder path (e.g. folder/job). A pasted Jenkins job or build URL is also accepted."`
	BuildNumber int    `json:"build_number,omitempty" jsonschema:"Build number. Optional when job_name is a build URL or build is set."`
	Build       string `json:"build,omitempty" jsonschema:"Alternative to build_number: lastBuild, lastCompletedBuild, lastSuccessfulBuild, lastFailedBuild or lastUnsuccessfulBuild"`
}

// permalinks maps lower-cased build aliases to Jenkins permalink names.
var permalinks = map[string]string{
	"last":                  "lastBuild",
	"latest":                "lastBuild",
	"lastbuild":             "lastBuild",
	"lastcompletedbuild":    "lastCompletedBuild",
	"lastsuccessfulbuild":   "lastSuccessfulBuild",
	"lastfailedbuild":       "lastFailedBuild",
	"lastunsuccessfulbuild": "lastUnsuccessfulBuild",
	"laststablebuild":       "lastStableBuild",
	"lastunstablebuild":     "lastUnstableBuild",
}

// buildJobPath builds a Jenkins job path supporting nested folders.
// Example: "folder1/folder2/jobName" -> "/job/folder1/job/folder2/job/jobName"
func buildJobPath(jobName string) string {
	var b strings.Builder
	for s := range strings.SplitSeq(jobName, "/") {
		if s == "" {
			continue
		}
		b.WriteString("/job/")
		b.WriteString(url.PathEscape(s))
	}
	return b.String()
}

// parseJobURL extracts the job path and an optional trailing build selector
// (number or permalink) from a Jenkins URL such as
// https://host/prefix/job/folder/job/name/123/console.
func parseJobURL(raw string) (job, build string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}
	segs := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	i := 0
	for i < len(segs) && segs[i] != "job" {
		i++
	}
	var names []string
	for i+1 < len(segs) && segs[i] == "job" {
		name, err := url.PathUnescape(segs[i+1])
		if err != nil {
			name = segs[i+1]
		}
		names = append(names, name)
		i += 2
	}
	if len(names) == 0 {
		return "", "", false
	}
	if i < len(segs) {
		if _, err := strconv.Atoi(segs[i]); err == nil {
			build = segs[i]
		} else if p, isPermalink := permalinks[strings.ToLower(segs[i])]; isPermalink {
			build = p
		}
	}
	return strings.Join(names, "/"), build, true
}

// parseJobRef normalizes a job_name argument, which may be a job path or URL.
func parseJobRef(s string) (job, build string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("missing required argument: job_name")
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		job, build, ok := parseJobURL(s)
		if !ok {
			return "", "", fmt.Errorf("could not find a job in URL %q (expected .../job/<name>/...)", s)
		}
		return job, build, nil
	}
	return strings.Trim(s, "/"), "", nil
}

// resolveBuild turns a BuildSelector into a concrete job path and build number,
// resolving permalinks such as lastFailedBuild against Jenkins.
func (opts *JenkinsOptions) resolveBuild(ctx context.Context, sel BuildSelector) (string, int, error) {
	job, urlBuild, err := parseJobRef(sel.JobName)
	if err != nil {
		return "", 0, err
	}
	if sel.BuildNumber > 0 {
		return job, sel.BuildNumber, nil
	}
	choice := strings.TrimPrefix(strings.TrimSpace(sel.Build), "#")
	if choice == "" {
		choice = urlBuild
	}
	if choice == "" {
		return "", 0, fmt.Errorf("missing build: pass build_number, or build (e.g. lastBuild, lastFailedBuild)")
	}
	if n, err := strconv.Atoi(choice); err == nil {
		if n <= 0 {
			return "", 0, fmt.Errorf("invalid build number %d", n)
		}
		return job, n, nil
	}
	permalink, ok := permalinks[strings.ToLower(choice)]
	if !ok {
		return "", 0, fmt.Errorf("invalid build %q: expected a build number, lastBuild, lastCompletedBuild, lastSuccessfulBuild, lastFailedBuild or lastUnsuccessfulBuild", sel.Build)
	}
	var data struct {
		Number int `json:"number"`
	}
	if err := opts.getJSON(ctx, buildJobPath(job)+"/"+permalink+"/api/json?tree=number", &data); err != nil {
		if isNotFound(err) {
			return "", 0, fmt.Errorf("job %q has no %s (or the job does not exist)", job, permalink)
		}
		return "", 0, err
	}
	return job, data.Number, nil
}

// jobAndBuildFromURL extracts job path and build number from a Jenkins build URL.
func jobAndBuildFromURL(raw string) (string, int) {
	job, build, ok := parseJobURL(raw)
	if !ok {
		return "", 0
	}
	n, _ := strconv.Atoi(build)
	return job, n
}
