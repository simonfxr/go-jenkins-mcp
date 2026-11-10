package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	buildTree       = "number,url,building,inProgress,result,timestamp,duration,estimatedDuration,displayName,actions[_class,parameters[name,value]]"
	buildDetailTree = "number,url,building,inProgress,result,timestamp,duration,estimatedDuration,displayName,description,builtOn,queueId," +
		"actions[_class,parameters[name,value],causes[shortDescription]]," +
		"changeSets[items[commitId,msg,author[fullName]]],changeSet[items[commitId,msg,author[fullName]]]," +
		"artifacts[relativePath]"
	paramDefTree = "property[parameterDefinitions[name,type,description,defaultParameterValue[value],choices]]"

	maxListedChanges           = 20
	maxListedArtifacts         = 20
	maxListedFilteredArtifacts = 200
)

// buildWire is the Jenkins JSON representation of a build.
type buildWire struct {
	Number            int    `json:"number"`
	URL               string `json:"url"`
	Building          bool   `json:"building"`
	InProgress        *bool  `json:"inProgress"`
	Result            string `json:"result"`
	Timestamp         int64  `json:"timestamp"`
	Duration          int64  `json:"duration"`
	EstimatedDuration int64  `json:"estimatedDuration"`
	DisplayName       string `json:"displayName"`
	Description       string `json:"description"`
	BuiltOn           string `json:"builtOn"`
	QueueID           int    `json:"queueId"`
	Actions           []struct {
		Parameters []struct {
			Name  string `json:"name"`
			Value any    `json:"value"`
		} `json:"parameters"`
		Causes []struct {
			ShortDescription string `json:"shortDescription"`
		} `json:"causes"`
	} `json:"actions"`
	ChangeSets []changeSetWire `json:"changeSets"`
	ChangeSet  *changeSetWire  `json:"changeSet"`
	Artifacts  []struct {
		RelativePath string `json:"relativePath"`
	} `json:"artifacts"`
}

type changeSetWire struct {
	Items []struct {
		CommitID string `json:"commitId"`
		Msg      string `json:"msg"`
		Author   struct {
			FullName string `json:"fullName"`
		} `json:"author"`
	} `json:"items"`
}

// params extracts the build parameters. Parameters without a value (e.g.
// separators) are skipped.
func (w *buildWire) params() map[string]string {
	var params map[string]string
	for _, a := range w.Actions {
		for _, p := range a.Parameters {
			if p.Value == nil {
				continue
			}
			if params == nil {
				params = map[string]string{}
			}
			params[p.Name] = formatParamValue(p.Value)
		}
	}
	return params
}

// toBuild converts the wire format into the summary representation.
func (w *buildWire) toBuild() Build {
	b := Build{
		Number:     w.Number,
		URL:        w.URL,
		Building:   w.Building,
		Result:     w.Result,
		Timestamp:  msTime(w.Timestamp),
		Duration:   msDuration(w.Duration),
		Parameters: w.params(),
		inProgress: w.Building,
	}
	if w.InProgress != nil {
		b.inProgress = *w.InProgress
	}
	if w.DisplayName != "#"+strconv.Itoa(w.Number) {
		b.DisplayName = w.DisplayName
	}
	if w.EstimatedDuration > 0 {
		b.EstimatedDuration = msDuration(w.EstimatedDuration)
	}
	if b.inProgress && w.Duration <= 0 && w.Timestamp > 0 {
		b.Duration = DurationMS(time.Since(time.UnixMilli(w.Timestamp)))
	}
	return b
}

// toBuildDetails additionally fills causes, changes and artifacts. Builds can
// have hundreds of artifacts, so only the first few are listed unless
// artifactFilter (a case-insensitive substring of the path) narrows them down.
func (w *buildWire) toBuildDetails(artifactFilter string) Build {
	b := w.toBuild()
	b.Description = w.Description
	b.BuiltOn = w.BuiltOn
	b.QueueID = w.QueueID
	for _, a := range w.Actions {
		for _, c := range a.Causes {
			if c.ShortDescription != "" {
				b.Causes = append(b.Causes, c.ShortDescription)
			}
		}
	}
	sets := w.ChangeSets
	if w.ChangeSet != nil {
		sets = append(sets, *w.ChangeSet)
	}
	for _, cs := range sets {
		for _, it := range cs.Items {
			b.ChangeCount++
			if len(b.Changes) >= maxListedChanges {
				continue
			}
			msg, _, _ := strings.Cut(strings.TrimSpace(it.Msg), "\n")
			commit := it.CommitID
			if len(commit) > 12 {
				commit = commit[:12]
			}
			b.Changes = append(b.Changes, BuildChange{Commit: commit, Author: it.Author.FullName, Message: msg})
		}
	}
	limit := maxListedArtifacts
	artifactFilter = strings.ToLower(strings.TrimSpace(artifactFilter))
	if artifactFilter != "" {
		limit = maxListedFilteredArtifacts
	}
	for _, a := range w.Artifacts {
		if artifactFilter != "" && !strings.Contains(strings.ToLower(a.RelativePath), artifactFilter) {
			continue
		}
		b.ArtifactCount++
		if len(b.Artifacts) < limit {
			b.Artifacts = append(b.Artifacts, a.RelativePath)
		}
	}
	if b.ChangeCount <= len(b.Changes) {
		b.ChangeCount = 0
	}
	if b.ArtifactCount <= len(b.Artifacts) {
		b.ArtifactCount = 0
	}
	return b
}

// formatParamValue renders a parameter value the way Jenkins expects it in forms.
func formatParamValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

// paramDefsWire is the Jenkins JSON representation of job properties holding
// parameter definitions.
type paramDefsWire []struct {
	ParameterDefinitions *[]struct {
		Name                  string `json:"name"`
		Type                  string `json:"type"`
		Description           string `json:"description"`
		DefaultParameterValue *struct {
			Value any `json:"value"`
		} `json:"defaultParameterValue"`
		Choices []string `json:"choices"`
	} `json:"parameterDefinitions"`
}

// definitions returns the parameter definitions (without layout-only
// separators) and whether the job is parameterized at all.
func (p paramDefsWire) definitions() (defs []BuildParameter, parameterized bool) {
	for _, prop := range p {
		if prop.ParameterDefinitions == nil {
			continue
		}
		parameterized = true
		for _, d := range *prop.ParameterDefinitions {
			if strings.Contains(d.Type, "Separator") {
				continue
			}
			def := BuildParameter{Name: d.Name, Type: d.Type, Description: d.Description, Choices: d.Choices}
			if d.DefaultParameterValue != nil {
				def.DefaultValue = d.DefaultParameterValue.Value
			}
			defs = append(defs, def)
		}
	}
	return defs, parameterized
}

// compactParams moves parameters into NonDefaultParameters, keeping only
// values that differ from the job's current defaults.
func compactParams(b *Build, defs []BuildParameter) {
	defaults := make(map[string]string, len(defs))
	for _, d := range defs {
		if d.DefaultValue != nil {
			defaults[d.Name] = formatParamValue(d.DefaultValue)
		}
	}
	for name, value := range b.Parameters {
		if def, ok := defaults[name]; ok && def == value {
			continue
		}
		if b.NonDefaultParameters == nil {
			b.NonDefaultParameters = map[string]string{}
		}
		b.NonDefaultParameters[name] = value
	}
	b.Parameters = nil
}

// getBuild fetches a build summary (state, result, parameters).
func (opts *JenkinsOptions) getBuild(ctx context.Context, jobName string, buildNumber int) (*Build, error) {
	var w buildWire
	if err := opts.getBuildWire(ctx, jobName, buildNumber, buildTree, &w); err != nil {
		return nil, err
	}
	b := w.toBuild()
	return &b, nil
}

// getBuildDetails fetches a build including causes, changes and artifacts.
func (opts *JenkinsOptions) getBuildDetails(ctx context.Context, jobName string, buildNumber int, artifactFilter string) (*Build, error) {
	var w buildWire
	if err := opts.getBuildWire(ctx, jobName, buildNumber, buildDetailTree, &w); err != nil {
		return nil, err
	}
	b := w.toBuildDetails(artifactFilter)
	return &b, nil
}

func (opts *JenkinsOptions) getBuildWire(ctx context.Context, jobName string, buildNumber int, tree string, w *buildWire) error {
	apiPath := fmt.Sprintf("%s/%d/api/json?tree=%s", buildJobPath(jobName), buildNumber, tree)
	if err := opts.getJSON(ctx, apiPath, w); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("job %q build #%d not found", jobName, buildNumber)
		}
		return err
	}
	return nil
}

// getJenkinsJob fetches a specific job with recent builds and parameter definitions.
func (opts *JenkinsOptions) getJenkinsJob(ctx context.Context, jobName string, maxBuilds int) (*Job, error) {
	apiPath := buildJobPath(jobName) + "/api/json?tree=" +
		"name,fullName,url,color,buildable,inQueue,description," +
		"builds[" + buildTree + "]{0," + strconv.Itoa(maxBuilds) + "}," + paramDefTree
	var data struct {
		Name        string        `json:"name"`
		FullName    string        `json:"fullName"`
		URL         string        `json:"url"`
		Color       string        `json:"color"`
		Buildable   bool          `json:"buildable"`
		InQueue     bool          `json:"inQueue"`
		Description string        `json:"description"`
		Builds      []buildWire   `json:"builds"`
		Property    paramDefsWire `json:"property"`
	}
	if err := opts.getJSON(ctx, apiPath, &data); err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("job %q not found", jobName)
		}
		return nil, err
	}

	defs, _ := data.Property.definitions()
	job := &Job{
		Name:        firstNonEmpty(data.FullName, data.Name, jobName),
		URL:         data.URL,
		Color:       data.Color,
		Buildable:   data.Buildable,
		InQueue:     data.InQueue,
		Description: data.Description,
		Parameters:  defs,
	}
	for i := range data.Builds {
		b := data.Builds[i].toBuild()
		compactParams(&b, defs)
		job.RecentBuilds = append(job.RecentBuilds, b)
	}
	sort.Slice(job.RecentBuilds, func(i, j int) bool {
		return job.RecentBuilds[i].Number > job.RecentBuilds[j].Number
	})

	// Include queued builds that belong to this job.
	if queued, err := opts.getQueuedBuilds(ctx); err == nil {
		for _, qb := range queued {
			if qb.JobName == job.Name || (job.URL != "" && qb.URL == job.URL) {
				job.QueuedBuilds = append(job.QueuedBuilds, qb)
			}
		}
	}
	return job, nil
}

// paramFilter is one build parameter condition of jenkins_search_builds.
type paramFilter struct {
	key    string
	value  string
	negate bool
	re     *regexp.Regexp
}

// parseParamFilter parses "key=value", "key!=value" or "key~=regex".
func parseParamFilter(s string) (paramFilter, error) {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return paramFilter{}, fmt.Errorf("invalid params filter %q: expected key=value, key!=value or key~=regex", s)
	}
	key, value := s[:i], s[i+1:]
	switch key[len(key)-1] {
	case '!':
		return paramFilter{key: key[:len(key)-1], value: value, negate: true}, nil
	case '~':
		re, err := regexp.Compile(value)
		if err != nil {
			return paramFilter{}, fmt.Errorf("invalid regex in params filter %q: %w", s, err)
		}
		return paramFilter{key: key[:len(key)-1], re: re}, nil
	}
	return paramFilter{key: key, value: value}, nil
}

func (f paramFilter) matches(params map[string]string) bool {
	got := params[f.key]
	if f.re != nil {
		return f.re.MatchString(got)
	}
	return (got == f.value) != f.negate
}

// searchBuilds fetches builds from Jenkins and filters by result and parameters.
func (opts *JenkinsOptions) searchBuilds(ctx context.Context, jobName string, args SearchBuildsToolArgs) (*SearchBuildsToolResponse, error) {
	var filters []paramFilter
	for _, p := range args.Params {
		f, err := parseParamFilter(p)
		if err != nil {
			return nil, err
		}
		filters = append(filters, f)
	}
	wantResult := strings.ToUpper(strings.TrimSpace(args.Result))

	// "builds" is capped at 100 entries by Jenkins; "allBuilds" is not.
	apiPath := buildJobPath(jobName) + "/api/json?tree=" +
		"allBuilds[" + buildTree + "]{0," + strconv.Itoa(args.MaxLookback) + "}," + paramDefTree
	var data struct {
		Builds   []buildWire   `json:"allBuilds"`
		Property paramDefsWire `json:"property"`
	}
	if err := opts.getJSON(ctx, apiPath, &data); err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("job %q not found", jobName)
		}
		return nil, err
	}
	defs, _ := data.Property.definitions()

	res := &SearchBuildsToolResponse{JobName: jobName, Builds: []Build{}, Scanned: len(data.Builds)}
	for i := range data.Builds {
		b := data.Builds[i].toBuild()
		switch wantResult {
		case "":
		case "BUILDING", "RUNNING":
			if !b.inProgress {
				continue
			}
		default:
			if b.inProgress || b.Result != wantResult {
				continue
			}
		}
		matched := true
		for _, f := range filters {
			if !f.matches(b.Parameters) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		compactParams(&b, defs)
		res.Builds = append(res.Builds, b)
		if len(res.Builds) >= args.Limit {
			break
		}
	}
	return res, nil
}

// jobsTree is the nested tree expression for listing jobs three folder levels deep.
var jobsTree = func() string {
	const fields = "name,fullName,url,color,buildable,description,lastBuild[number,building,result,timestamp,duration]"
	tree := fields
	for range 2 {
		tree = fields + ",jobs[" + tree + "]"
	}
	return "jobs[" + tree + "]"
}()

type jobWire struct {
	Name        string     `json:"name"`
	FullName    string     `json:"fullName"`
	URL         string     `json:"url"`
	Color       string     `json:"color"`
	Buildable   bool       `json:"buildable"`
	Description string     `json:"description"`
	LastBuild   *buildWire `json:"lastBuild"`
	Jobs        *[]jobWire `json:"jobs"`
}

// getJenkinsJobs lists jobs, descending into folders. folder restricts the
// listing to one folder; filter is a case-insensitive substring of the job path.
func (opts *JenkinsOptions) getJenkinsJobs(ctx context.Context, folder, filter string) ([]Job, error) {
	var data struct {
		Jobs []jobWire `json:"jobs"`
	}
	if err := opts.getJSON(ctx, buildJobPath(folder)+"/api/json?tree="+jobsTree, &data); err != nil {
		if isNotFound(err) && folder != "" {
			return nil, fmt.Errorf("folder %q not found", folder)
		}
		return nil, err
	}
	filter = strings.ToLower(strings.TrimSpace(filter))
	jobs := []Job{}
	var walk func(items []jobWire, parent string)
	walk = func(items []jobWire, parent string) {
		for _, it := range items {
			name := it.FullName
			if name == "" {
				name = strings.TrimPrefix(parent+"/"+it.Name, "/")
			}
			isFolder := it.Jobs != nil
			if filter == "" || strings.Contains(strings.ToLower(name), filter) {
				job := Job{Name: name, URL: it.URL, Color: it.Color, Buildable: it.Buildable, Description: truncate(it.Description, 200)}
				if isFolder {
					job.Type = "folder"
				}
				if it.LastBuild != nil {
					b := it.LastBuild.toBuild()
					job.LastBuild = &b
				}
				jobs = append(jobs, job)
			}
			if isFolder {
				walk(*it.Jobs, name)
			}
		}
	}
	walk(data.Jobs, strings.Trim(folder, "/"))
	return jobs, nil
}

// getRunningBuilds fetches currently running builds from all executors.
// Pipeline builds occupy a one-off executor on the controller plus regular
// executors for their node blocks, so entries are merged by build URL.
func (opts *JenkinsOptions) getRunningBuilds(ctx context.Context) ([]RunningBuild, error) {
	type executorWire struct {
		CurrentExecutable *struct {
			URL             string `json:"url"`
			FullDisplayName string `json:"fullDisplayName"`
			Timestamp       int64  `json:"timestamp"`
		} `json:"currentExecutable"`
		Idle        bool `json:"idle"`
		LikelyStuck bool `json:"likelyStuck"`
		Progress    *int `json:"progress"`
	}
	var data struct {
		Computer []struct {
			DisplayName     string         `json:"displayName"`
			Executors       []executorWire `json:"executors"`
			OneOffExecutors []executorWire `json:"oneOffExecutors"`
		} `json:"computer"`
	}
	const execTree = "[currentExecutable[url,fullDisplayName,timestamp],idle,likelyStuck,progress]"
	if err := opts.getJSON(ctx, "/computer/api/json?tree=computer[displayName,executors"+execTree+",oneOffExecutors"+execTree+"]", &data); err != nil {
		return nil, err
	}

	builds := []RunningBuild{}
	index := map[string]int{}
	add := func(node string, e executorWire, oneOff bool) {
		if e.Idle || e.CurrentExecutable == nil {
			return
		}
		ex := e.CurrentExecutable
		jobName, number := jobAndBuildFromURL(ex.URL)
		if jobName == "" {
			jobName, number = parseJobNameAndBuildNumber(ex.FullDisplayName)
		}
		key := ex.URL
		if key == "" {
			key = ex.FullDisplayName
		}
		if i, ok := index[key]; ok {
			rb := &builds[i]
			// Prefer the agent actually doing the work over the controller's one-off executor.
			if !oneOff && node != "" {
				rb.Node = node
			}
			if rb.Progress == nil || (e.Progress != nil && *e.Progress > *rb.Progress) {
				rb.Progress = e.Progress
			}
			rb.LikelyStuck = rb.LikelyStuck || e.LikelyStuck
			return
		}
		start := time.UnixMilli(ex.Timestamp)
		rb := RunningBuild{
			JobName:     jobName,
			BuildNumber: number,
			URL:         ex.URL,
			Node:        node,
			StartTime:   msTime(ex.Timestamp),
			Progress:    e.Progress,
			LikelyStuck: e.LikelyStuck,
		}
		if ex.Timestamp > 0 {
			rb.Duration = DurationMS(time.Since(start))
		}
		if rb.Progress != nil && *rb.Progress < 0 {
			rb.Progress = nil
		}
		index[key] = len(builds)
		builds = append(builds, rb)
	}
	for _, c := range data.Computer {
		for _, e := range c.OneOffExecutors {
			add(c.DisplayName, e, true)
		}
	}
	for _, c := range data.Computer {
		for _, e := range c.Executors {
			add(c.DisplayName, e, false)
		}
	}
	return builds, nil
}

// parseJobNameAndBuildNumber extracts job name and build number from a Jenkins
// full display name ("jobName #buildNumber"). Used only when no URL is available.
func parseJobNameAndBuildNumber(fullDisplayName string) (string, int) {
	if i := strings.LastIndex(fullDisplayName, " #"); i >= 0 {
		if buildNumber, err := strconv.Atoi(fullDisplayName[i+2:]); err == nil {
			return fullDisplayName[:i], buildNumber
		}
	}
	return fullDisplayName, 0
}

// getNodes lists Jenkins nodes with their executor usage and labels.
func (opts *JenkinsOptions) getNodes(ctx context.Context) ([]Node, error) {
	var data struct {
		Computer []struct {
			DisplayName        string `json:"displayName"`
			Offline            bool   `json:"offline"`
			OfflineCauseReason string `json:"offlineCauseReason"`
			NumExecutors       int    `json:"numExecutors"`
			AssignedLabels     []struct {
				Name string `json:"name"`
			} `json:"assignedLabels"`
			Executors []struct {
				Idle bool `json:"idle"`
			} `json:"executors"`
		} `json:"computer"`
	}
	if err := opts.getJSON(ctx, "/computer/api/json?tree=computer[displayName,offline,offlineCauseReason,numExecutors,assignedLabels[name],executors[idle]]", &data); err != nil {
		return nil, err
	}
	nodes := []Node{}
	for _, c := range data.Computer {
		n := Node{Name: c.DisplayName, Online: !c.Offline, Executors: c.NumExecutors, OfflineReason: truncate(c.OfflineCauseReason, 200)}
		for _, e := range c.Executors {
			if !e.Idle {
				n.BusyExecutors++
			}
		}
		for _, l := range c.AssignedLabels {
			if l.Name != c.DisplayName {
				n.Labels = append(n.Labels, l.Name)
			}
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// downloadArtifact saves a build artifact to a local file and returns its
// absolute path and size.
func (opts *JenkinsOptions) downloadArtifact(ctx context.Context, jobName string, buildNumber int, artifact, dest string) (string, int64, error) {
	rel := filepath.ToSlash(filepath.Clean("/" + strings.TrimSpace(artifact)))[1:]
	if rel == "" {
		return "", 0, fmt.Errorf("missing required argument: artifact (relative path as listed by jenkins_get_build)")
	}
	var escaped []string
	for seg := range strings.SplitSeq(rel, "/") {
		escaped = append(escaped, url.PathEscape(seg))
	}
	apiPath := fmt.Sprintf("%s/%d/artifact/%s", buildJobPath(jobName), buildNumber, strings.Join(escaped, "/"))
	resp, err := opts.request(ctx, opts.LogsClient, http.MethodGet, apiPath, nil, map[string]string{"Accept": "*/*"})
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", 0, fmt.Errorf("artifact %q not found in job %q build #%d", rel, jobName, buildNumber)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, newAPIError(resp)
	}

	if dest == "" {
		dest = filepath.Join(os.TempDir(), "go-jenkins-mcp-artifacts", safePathSegment(strings.ReplaceAll(jobName, "/", "_"))+"-"+strconv.Itoa(buildNumber), filepath.FromSlash(rel))
	}
	dest, err = filepath.Abs(dest)
	if err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", 0, fmt.Errorf("cannot create directory for artifact: %w (pass a writable path)", err)
	}
	f, err := os.Create(dest)
	if err != nil {
		return "", 0, fmt.Errorf("cannot write artifact: %w (pass a writable path)", err)
	}
	n, err := io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(dest)
		return "", 0, fmt.Errorf("failed to download artifact: %w", err)
	}
	return dest, n, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// truncate shortens s to at most maxLen bytes without splitting UTF-8 sequences.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return strings.ToValidUTF8(s[:maxLen], "") + "…"
}
