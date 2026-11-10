package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxLogLineLength     = 2000 // longer lines are shortened in log excerpts
	maxMatchLineLength   = 500
	maxContextLineLength = 300

	// defaultErrorPattern is used by jenkins_grep_build_log when no pattern is given.
	defaultErrorPattern = `(?i)\b(error|errors|fatal|exception|failed|failure|panic|traceback|segfault|denied|cannot|no such file)\b|\bFAIL\b|exit (code|status) [1-9]`
)

// timestampRe matches the per-line prefix added by the Pipeline timestamper,
// e.g. "[2026-11-10T08:19:16.593Z] ".
var timestampRe = regexp.MustCompile(`^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\] `)

// BuildLogs describes a slice of a cleaned build log. Offsets and line numbers
// refer to the cleaned log and are consistent across all log tools and the
// file written by jenkins_download_build_log.
type BuildLogs struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	Offset      int    `json:"offset"`              // byte offset of the first returned line
	NextOffset  int    `json:"nextOffset"`          // offset to continue reading from
	StartLine   int    `json:"startLine,omitempty"` // 1-based
	EndLine     int    `json:"endLine,omitempty"`   // inclusive
	TotalSize   int    `json:"totalSize"`
	TotalLines  int    `json:"totalLines"`
	Complete    bool   `json:"complete"` // false while the build is still writing its log
	HasMore     bool   `json:"hasMore"`  // more log follows nextOffset (now, or later while the build runs)
	Logs        string `json:"logs"`
}

// LogMatch is one matching line of jenkins_grep_build_log.
type LogMatch struct {
	Line   int      `json:"line"`   // 1-based line number
	Offset int      `json:"offset"` // byte offset of the line start
	Text   string   `json:"text"`
	Before []string `json:"before,omitempty"`
	After  []string `json:"after,omitempty"`
}

// GrepBuildLogToolResponse is the result payload for jenkins_grep_build_log.
type GrepBuildLogToolResponse struct {
	JobName      string     `json:"jobName"`
	BuildNumber  int        `json:"buildNumber"`
	Pattern      string     `json:"pattern"`
	TotalMatches int        `json:"totalMatches"`
	Truncated    bool       `json:"truncated,omitempty"`  // more matches exist than were returned
	NextOffset   int        `json:"nextOffset,omitempty"` // pass as offset to get the following matches
	TotalSize    int        `json:"totalSize"`
	TotalLines   int        `json:"totalLines"`
	Complete     bool       `json:"complete"`
	Matches      []LogMatch `json:"matches"`
}

// DownloadBuildLogToolResponse is the result payload for jenkins_download_build_log.
type DownloadBuildLogToolResponse struct {
	JobName     string `json:"jobName"`
	BuildNumber int    `json:"buildNumber"`
	Path        string `json:"path"`
	Size        int    `json:"size"`
	Lines       int    `json:"lines"`
	Complete    bool   `json:"complete"`
}

// countLines returns the number of lines in data; a trailing fragment without
// line terminator counts as a line.
func countLines(data []byte) int {
	n := bytes.Count(data, []byte{'\n'})
	if len(data) > 0 && data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// lineStart returns the offset of the start of the line containing off.
func lineStart(data []byte, off int) int {
	off = max(0, min(off, len(data)))
	return bytes.LastIndexByte(data[:off], '\n') + 1
}

// offsetOfLine returns the offset of the 1-based line; len(data) if it does not exist.
func offsetOfLine(data []byte, line int) int {
	off := 0
	for i := 1; i < line; i++ {
		nl := bytes.IndexByte(data[off:], '\n')
		if nl < 0 {
			return len(data)
		}
		off += nl + 1
	}
	return off
}

// renderLine prepares a log line for output: optionally drops the timestamp
// prefix and shortens overlong lines.
func renderLine(line []byte, timestamps bool, maxLen int) string {
	if !timestamps {
		line = stripTimestamp(line)
	}
	if len(line) <= maxLen {
		return string(line)
	}
	return strings.ToValidUTF8(string(line[:maxLen]), "") + fmt.Sprintf("…[+%d bytes]", len(line)-maxLen)
}

func stripTimestamp(line []byte) []byte {
	if len(line) > 0 && line[0] == '[' {
		if loc := timestampRe.FindIndex(line); loc != nil {
			return line[loc[1]:]
		}
	}
	return line
}

// logSlice is a run of whole lines taken from a log.
type logSlice struct {
	text       string
	offset     int
	nextOffset int
	startLine  int
	lines      int
}

// readLines returns whole lines starting at the line containing off, limited
// to maxBytes of rendered text (at least one line) and maxLines (0 = no limit).
func readLines(data []byte, off, maxBytes, maxLines int, timestamps bool) logSlice {
	start := lineStart(data, off)
	res := logSlice{offset: start, nextOffset: start, startLine: bytes.Count(data[:start], []byte{'\n'}) + 1}
	var sb strings.Builder
	for pos := start; pos < len(data); {
		end := len(data)
		next := end
		if nl := bytes.IndexByte(data[pos:], '\n'); nl >= 0 {
			end = pos + nl
			next = end + 1
		}
		rendered := renderLine(data[pos:end], timestamps, maxLogLineLength)
		if res.lines > 0 && sb.Len()+len(rendered)+1 > maxBytes {
			break
		}
		sb.WriteString(rendered)
		sb.WriteByte('\n')
		res.lines++
		pos = next
		res.nextOffset = next
		if maxLines > 0 && res.lines >= maxLines {
			break
		}
	}
	res.text = sb.String()
	return res
}

// tailLines returns the last whole lines of a log within the given limits.
func tailLines(data []byte, maxBytes, maxLines int, timestamps bool) logSlice {
	start, size, lines := len(data), 0, 0
	for start > 0 {
		end := start
		if data[end-1] == '\n' {
			end--
		}
		ls := bytes.LastIndexByte(data[:end], '\n') + 1
		n := len(renderLine(data[ls:end], timestamps, maxLogLineLength)) + 1
		if lines > 0 && size+n > maxBytes {
			break
		}
		size += n
		lines++
		start = ls
		if maxLines > 0 && lines >= maxLines {
			break
		}
	}
	return readLines(data, start, size+1, lines, timestamps)
}

func newBuildLogs(jobName string, buildNumber int, snap *logSnapshot, s logSlice) *BuildLogs {
	res := &BuildLogs{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Offset:      s.offset,
		NextOffset:  s.nextOffset,
		TotalSize:   len(snap.Data),
		TotalLines:  countLines(snap.Data),
		Complete:    snap.Complete,
		HasMore:     s.nextOffset < len(snap.Data) || !snap.Complete,
		Logs:        s.text,
	}
	if s.lines > 0 {
		res.StartLine = s.startLine
		res.EndLine = s.startLine + s.lines - 1
	}
	return res
}

// getBuildLogs returns a line-aligned portion of the cleaned build log.
func (opts *JenkinsOptions) getBuildLogs(ctx context.Context, jobName string, buildNumber int, args GetBuildLogsToolArgs) (*BuildLogs, error) {
	snap, err := opts.getLog(ctx, jobName, buildNumber)
	if err != nil {
		return nil, err
	}
	off := max(args.Offset, 0)
	if args.StartLine > 0 {
		off = offsetOfLine(snap.Data, args.StartLine)
	}
	return newBuildLogs(jobName, buildNumber, snap, readLines(snap.Data, off, args.Length, args.MaxLines, args.Timestamps)), nil
}

// getBuildLogTail returns the last lines of the cleaned build log.
func (opts *JenkinsOptions) getBuildLogTail(ctx context.Context, jobName string, buildNumber int, args GetBuildLogTailToolArgs) (*BuildLogs, error) {
	snap, err := opts.getLog(ctx, jobName, buildNumber)
	if err != nil {
		return nil, err
	}
	return newBuildLogs(jobName, buildNumber, snap, tailLines(snap.Data, args.MaxLength, args.MaxLines, args.Timestamps)), nil
}

// grepOptions configures grepLog.
type grepOptions struct {
	pattern    *regexp.Regexp
	exclude    *regexp.Regexp
	offset     int
	context    int
	maxMatches int
	tail       bool
	timestamps bool
}

// grepLog searches the lines of a log. Patterns are matched against lines as
// they are displayed (i.e. without timestamp prefix unless timestamps is set).
func grepLog(data []byte, o grepOptions) (matches []LogMatch, total, nextOffset int) {
	// Index all line starts so context lines can be addressed.
	starts := make([]int, 0, 1024)
	for pos := 0; pos < len(data); {
		starts = append(starts, pos)
		nl := bytes.IndexByte(data[pos:], '\n')
		if nl < 0 {
			break
		}
		pos += nl + 1
	}
	lineAt := func(i int) []byte {
		end := len(data)
		if i+1 < len(starts) {
			end = starts[i+1] - 1
		} else if end > starts[i] && data[end-1] == '\n' {
			end--
		}
		line := data[starts[i]:end]
		if !o.timestamps {
			line = stripTimestamp(line)
		}
		return line
	}

	first := lineStart(data, o.offset)
	var hits []int
	for i := range starts {
		if starts[i] < first {
			continue
		}
		line := lineAt(i)
		if o.pattern.Match(line) && (o.exclude == nil || !o.exclude.Match(line)) {
			hits = append(hits, i)
		}
	}
	total = len(hits)
	selected := hits
	if len(selected) > o.maxMatches {
		if o.tail {
			selected = selected[len(selected)-o.maxMatches:]
		} else {
			selected = selected[:o.maxMatches]
			if last := selected[len(selected)-1]; last+1 < len(starts) {
				nextOffset = starts[last+1]
			} else {
				nextOffset = len(data)
			}
		}
	}

	matches = make([]LogMatch, 0, len(selected))
	emitted := -1 // index of the last line already shown
	for n, i := range selected {
		m := LogMatch{Line: i + 1, Offset: starts[i], Text: excerptAround(lineAt(i), o.pattern, maxMatchLineLength)}
		for j := max(i-o.context, emitted+1); j < i; j++ {
			m.Before = append(m.Before, renderLine(lineAt(j), true, maxContextLineLength))
		}
		limit := min(i+o.context, len(starts)-1)
		if n+1 < len(selected) {
			limit = min(limit, selected[n+1]-1)
		}
		for j := i + 1; j <= limit; j++ {
			m.After = append(m.After, renderLine(lineAt(j), true, maxContextLineLength))
		}
		emitted = max(limit, i)
		matches = append(matches, m)
	}
	return matches, total, nextOffset
}

// excerptAround shortens a long line to a window around its first match.
func excerptAround(line []byte, re *regexp.Regexp, maxLen int) string {
	if len(line) <= maxLen {
		return string(line)
	}
	from := 0
	if loc := re.FindIndex(line); loc != nil && loc[0] > maxLen/3 {
		from = loc[0] - maxLen/3
	}
	to := min(from+maxLen, len(line))
	s := strings.ToValidUTF8(string(line[from:to]), "")
	if from > 0 {
		s = "…" + s
	}
	if to < len(line) {
		s += fmt.Sprintf("…[+%d bytes]", len(line)-to)
	}
	return s
}

// grepBuildLog searches the cleaned build log for a regular expression.
func (opts *JenkinsOptions) grepBuildLog(ctx context.Context, jobName string, buildNumber int, args GrepBuildLogToolArgs) (*GrepBuildLogToolResponse, error) {
	pattern := args.Pattern
	if strings.TrimSpace(pattern) == "" {
		pattern = defaultErrorPattern
	} else if args.IgnoreCase {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern (RE2 syntax): %w", err)
	}
	var exclude *regexp.Regexp
	if pattern == defaultErrorPattern {
		exclude = defaultNoiseRe
	}
	if args.Exclude != "" {
		ex := args.Exclude
		if args.IgnoreCase {
			ex = "(?i)" + ex
		}
		if exclude, err = regexp.Compile(ex); err != nil {
			return nil, fmt.Errorf("invalid exclude pattern (RE2 syntax): %w", err)
		}
	}

	snap, err := opts.getLog(ctx, jobName, buildNumber)
	if err != nil {
		return nil, err
	}
	matches, total, next := grepLog(snap.Data, grepOptions{
		pattern:    re,
		exclude:    exclude,
		offset:     max(args.Offset, 0),
		context:    max(0, min(args.Context, 20)),
		maxMatches: args.MaxMatches,
		tail:       args.Tail,
		timestamps: args.Timestamps,
	})
	return &GrepBuildLogToolResponse{
		JobName:      jobName,
		BuildNumber:  buildNumber,
		Pattern:      pattern,
		TotalMatches: total,
		Truncated:    total > len(matches),
		NextOffset:   next,
		TotalSize:    len(snap.Data),
		TotalLines:   countLines(snap.Data),
		Complete:     snap.Complete,
		Matches:      matches,
	}, nil
}

// downloadBuildLog makes the full cleaned log available as a local file.
// Without an explicit destination the cache file is used when there is one,
// otherwise a temporary file is written.
func (opts *JenkinsOptions) downloadBuildLog(ctx context.Context, jobName string, buildNumber int, dest string) (*DownloadBuildLogToolResponse, error) {
	snap, err := opts.getLog(ctx, jobName, buildNumber)
	if err != nil {
		return nil, err
	}
	res := &DownloadBuildLogToolResponse{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Size:        len(snap.Data),
		Lines:       countLines(snap.Data),
		Complete:    snap.Complete,
	}
	switch {
	case dest != "":
		abs, err := filepath.Abs(dest)
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(abs, snap.Data); err != nil {
			return nil, fmt.Errorf("cannot write log to %s: %w (pass another path, or output=text to get the log inline)", abs, err)
		}
		res.Path = abs
	case snap.Path != "":
		res.Path = snap.Path
	default:
		name := fmt.Sprintf("jenkins-%s-%s-*.log", safePathSegment(strings.ReplaceAll(jobName, "/", "_")), strconv.Itoa(buildNumber))
		f, err := os.CreateTemp("", name)
		if err != nil {
			return nil, fmt.Errorf("cannot write log to a temporary file: %w (pass path, or output=text to get the log inline)", err)
		}
		_, err = f.Write(snap.Data)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(f.Name())
			return nil, fmt.Errorf("cannot write log to a temporary file: %w (pass path, or output=text to get the log inline)", err)
		}
		res.Path = f.Name()
	}
	return res, nil
}
