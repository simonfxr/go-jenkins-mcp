package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// writeMultipartLog answers like Jenkins' progressiveText in multipart mode.
func writeMultipartLog(w http.ResponseWriter, text string, start, end int64, completed bool) {
	const b = "test-boundary"
	w.Header().Set("Content-Type", "multipart/form-data;boundary="+b+";charset=utf-8")
	fmt.Fprintf(w, "--%s\r\nContent-Disposition: form-data;name=text\r\nContent-Type: text/plain;charset=utf-8\r\n\r\n%s\r\n--%s\r\n"+
		"Content-Disposition: form-data;name=meta\r\nContent-Type: application/json;charset=utf-8\r\n\r\n"+
		"{\"completed\":%t,\"start\":%d,\"end\":%d}\r\n--%s--", b, text, b, completed, start, end, b)
}

func TestCleanLog(t *testing.T) {
	raw := "[ts] Started by \x1b[8mha:////4AAAAbase64+/==\x1b[0muser\r\n" +
		"\x1b[1;31mred error\x1b[0m and \x1b]0;title\x07plain\n" +
		"progress 1%\rprogress 50%\rprogress 100%\r\n" +
		"no newline at end"
	var buf bytes.Buffer
	if err := cleanLog(&buf, strings.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	want := "[ts] Started by user\nred error and plain\nprogress 100%\nno newline at end"
	if buf.String() != want {
		t.Errorf("got %q\nwant %q", buf.String(), want)
	}
}

func sampleLog(lines int) []byte {
	var sb strings.Builder
	for i := 1; i <= lines; i++ {
		fmt.Fprintf(&sb, "[2026-11-10T08:19:%02d.000Z] line %d\n", i%60, i)
	}
	return []byte(sb.String())
}

func TestReadLinesIsLineAlignedAndPageable(t *testing.T) {
	data := sampleLog(50)
	var got strings.Builder
	off, pages := 0, 0
	for off < len(data) {
		s := readLines(data, off, 60, 0, false)
		if s.lines == 0 || s.nextOffset <= off {
			t.Fatalf("no progress at offset %d: %+v", off, s)
		}
		got.WriteString(s.text)
		off = s.nextOffset
		pages++
	}
	var want strings.Builder
	for i := 1; i <= 50; i++ {
		fmt.Fprintf(&want, "line %d\n", i)
	}
	if got.String() != want.String() || pages < 5 {
		t.Errorf("paging lost or duplicated content (pages=%d)", pages)
	}

	// An offset inside a line snaps back to the start of that line.
	mid := offsetOfLine(data, 10) + 5
	s := readLines(data, mid, 1000, 2, true)
	if s.startLine != 10 || s.lines != 2 || !strings.HasPrefix(s.text, "[2026-11-10T08:19:10.000Z] line 10\n") {
		t.Errorf("unexpected slice: %+v", s)
	}
	// Reading at or beyond the end yields nothing instead of restarting.
	if s := readLines(data, len(data)+100, 1000, 0, false); s.lines != 0 || s.nextOffset != len(data) {
		t.Errorf("unexpected slice past end: %+v", s)
	}
	if got := offsetOfLine(data, 999); got != len(data) {
		t.Errorf("offsetOfLine past end = %d", got)
	}
}

func TestTailLines(t *testing.T) {
	data := sampleLog(50)
	s := tailLines(data, 1<<20, 3, false)
	if s.text != "line 48\nline 49\nline 50\n" || s.startLine != 48 || s.nextOffset != len(data) {
		t.Errorf("unexpected tail: %+v", s)
	}
	if s := tailLines(data, 20, 0, false); s.text != "line 49\nline 50\n" {
		t.Errorf("unexpected byte-limited tail: %q", s.text)
	}
	if s := tailLines(nil, 100, 0, false); s.lines != 0 || s.text != "" {
		t.Errorf("unexpected tail of empty log: %+v", s)
	}
	long := []byte("short\n" + strings.Repeat("x", 5000) + "\n")
	if s := tailLines(long, 100, 1, false); !strings.HasSuffix(s.text, "…[+3000 bytes]\n") || len(s.text) > 2100 {
		t.Errorf("long line not shortened: %d bytes", len(s.text))
	}
}

func TestGrepLog(t *testing.T) {
	data := []byte("[2026-11-10T08:19:16.593Z] one\nerror: a\nctx\nerror: b\ntwo\nthree\nERROR: c\nlast\n")
	re := regexp.MustCompile(`^error`)

	matches, total, next := grepLog(data, grepOptions{pattern: re, maxMatches: 10, context: 2})
	if total != 2 || len(matches) != 2 || next != 0 {
		t.Fatalf("total=%d matches=%+v next=%d", total, matches, next)
	}
	m := matches[0]
	if m.Line != 2 || m.Offset != offsetOfLine(data, 2) || m.Text != "error: a" || fmt.Sprint(m.Before) != "[one]" || fmt.Sprint(m.After) != "[ctx]" {
		t.Errorf("unexpected first match: %+v", m)
	}
	// Context lines are never repeated between adjacent matches.
	if m := matches[1]; m.Line != 4 || len(m.Before) != 0 || fmt.Sprint(m.After) != "[two three]" {
		t.Errorf("unexpected second match: %+v", m)
	}

	ci := regexp.MustCompile(`(?i)^error`)
	matches, total, next = grepLog(data, grepOptions{pattern: ci, maxMatches: 2})
	if total != 3 || len(matches) != 2 || next != offsetOfLine(data, 5) {
		t.Errorf("total=%d len=%d next=%d", total, len(matches), next)
	}
	matches, total, _ = grepLog(data, grepOptions{pattern: ci, maxMatches: 10, offset: next})
	if total != 1 || matches[0].Line != 7 {
		t.Errorf("continuation: total=%d matches=%+v", total, matches)
	}
	matches, _, _ = grepLog(data, grepOptions{pattern: ci, maxMatches: 1, tail: true})
	if len(matches) != 1 || matches[0].Line != 7 {
		t.Errorf("tail: %+v", matches)
	}
	matches, _, _ = grepLog(data, grepOptions{pattern: ci, exclude: regexp.MustCompile(`: b`), maxMatches: 10})
	if len(matches) != 2 || matches[1].Line != 7 {
		t.Errorf("exclude: %+v", matches)
	}
	// Timestamps take part in matching only when requested.
	if _, total, _ := grepLog(data, grepOptions{pattern: regexp.MustCompile(`^one`), maxMatches: 1}); total != 1 {
		t.Errorf("timestamp prefix was not stripped before matching")
	}
	if _, total, _ := grepLog(data, grepOptions{pattern: regexp.MustCompile(`^one`), maxMatches: 1, timestamps: true}); total != 0 {
		t.Errorf("timestamp prefix was stripped although timestamps were requested")
	}
	if !defaultErrorRe.MatchString("script returned exit code 1") || !defaultErrorRe.MatchString("FAILED: foo.o") || defaultErrorRe.MatchString("all good") {
		t.Errorf("default error pattern misbehaves")
	}
}

func TestGetLogCachesFinishedLogsOnDisk(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.handle("GET /job/a/job/b/3/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "multipart/form-data" {
			t.Errorf("unexpected Accept %q", got)
		}
		writeMultipartLog(w, "hello\r\nworld\n", 0, 99, true)
	})
	for range 3 {
		snap, err := opts.getLog(context.Background(), "a/b", 3)
		if err != nil {
			t.Fatal(err)
		}
		if string(snap.Data) != "hello\nworld\n" || !snap.Complete || snap.Path == "" {
			t.Fatalf("unexpected snapshot: %q complete=%v path=%q", snap.Data, snap.Complete, snap.Path)
		}
		if onDisk, err := os.ReadFile(snap.Path); err != nil || string(onDisk) != "hello\nworld\n" {
			t.Fatalf("cache file: %q %v", onDisk, err)
		}
	}
	if n := f.count("GET /job/a/job/b/3/logText/progressiveText"); n != 1 {
		t.Errorf("finished log was fetched %d times, want 1", n)
	}
}

func TestGetLogFollowsRunningBuildIncrementally(t *testing.T) {
	f, opts := newFakeJenkins(t)
	var starts []string
	step := 0
	f.handle("GET /job/build/1/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
		starts = append(starts, r.URL.Query().Get("start"))
		step++
		switch step {
		case 1:
			writeMultipartLog(w, "one\n", 0, 10, false)
		case 2:
			writeMultipartLog(w, "", 10, 10, false)
		case 3:
			writeMultipartLog(w, "two\n", 10, 25, false)
		default:
			writeMultipartLog(w, "three\n", 25, 40, true)
		}
	})
	want := []string{"one\n", "one\n", "one\ntwo\n", "one\ntwo\nthree\n"}
	var first *logSnapshot
	for i, w := range want {
		snap, err := opts.getLog(context.Background(), "build", 1)
		if err != nil {
			t.Fatal(err)
		}
		if string(snap.Data) != w || snap.Complete != (i == 3) {
			t.Errorf("step %d: %q complete=%v", i, snap.Data, snap.Complete)
		}
		if i == 0 {
			first = snap
		}
	}
	if string(first.Data) != "one\n" {
		t.Errorf("earlier snapshot was modified: %q", first.Data)
	}
	if got := strings.Join(starts, ","); got != "0,10,10,25" {
		t.Errorf("unexpected resume offsets %s", got)
	}

	// A paged read at the end of a running log reports that more may follow.
	f.handle("GET /job/build/2/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
		writeMultipartLog(w, "", 0, 0, false)
	})
	logs, err := opts.getBuildLogs(context.Background(), "build", 2, GetBuildLogsToolArgs{Length: 100})
	if err != nil || logs.Logs != "" || !logs.HasMore || logs.Complete {
		t.Errorf("logs=%+v err=%v", logs, err)
	}
}

func TestGetLogRestartsWhenJenkinsRollsOver(t *testing.T) {
	f, opts := newFakeJenkins(t)
	step := 0
	f.handle("GET /job/build/1/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
		step++
		if step == 1 {
			writeMultipartLog(w, "old\n", 0, 500, false)
			return
		}
		writeMultipartLog(w, "fresh\n", 0, 6, true) // start beyond the log: sent in full from 0
	})
	_, _ = opts.getLog(context.Background(), "build", 1)
	snap, err := opts.getLog(context.Background(), "build", 1)
	if err != nil || string(snap.Data) != "fresh\n" {
		t.Errorf("data=%q err=%v", snap.Data, err)
	}
}

func TestGetLogLegacyPlainTextResponse(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.handle("GET /job/build/1/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
		w.Header().Set("X-Text-Size", "1234")
		if r.URL.Query().Get("start") == "0" {
			w.Header().Set("X-More-Data", "true")
			fmt.Fprint(w, "a \x1b[8mha:AAAA\x1b[0mnote\r\n")
			return
		}
		if r.URL.Query().Get("start") != "1234" {
			t.Errorf("unexpected start %q", r.URL.Query().Get("start"))
		}
		fmt.Fprint(w, "done\r\n")
	})
	snap, err := opts.getLog(context.Background(), "build", 1)
	if err != nil || string(snap.Data) != "a note\n" || snap.Complete {
		t.Fatalf("data=%q complete=%v err=%v", snap.Data, snap.Complete, err)
	}
	snap, err = opts.getLog(context.Background(), "build", 1)
	if err != nil || string(snap.Data) != "a note\ndone\n" || !snap.Complete {
		t.Fatalf("data=%q complete=%v err=%v", snap.Data, snap.Complete, err)
	}
}

// The server must keep working when the cache directory cannot be written,
// e.g. inside a sandbox.
func TestLogToolsWorkWithoutWritableCache(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	unwritable := filepath.Join(blocker, "cache")
	sharedFallback := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(sharedFallback, 0o755); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ cacheDir, fallback string }{
		"unwritable":                       {unwritable, ""},
		"unwritable, fallback not private": {unwritable, sharedFallback},
		"disabled":                         {"", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, opts := newFakeJenkins(t)
			opts.Logs = newLogStore(c.cacheDir, c.fallback, opts.URL)
			f.handle("GET /job/build/1/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
				writeMultipartLog(w, "a\nerror: b\nc\n", 0, 13, true)
			})
			ctx := context.Background()
			tail, err := opts.getBuildLogTail(ctx, "build", 1, GetBuildLogTailToolArgs{MaxLength: 100, MaxLines: 1})
			if err != nil || tail.Logs != "c\n" || tail.StartLine != 3 || tail.TotalLines != 3 || !tail.Complete || tail.HasMore {
				t.Fatalf("tail=%+v err=%v", tail, err)
			}
			grep, err := opts.grepBuildLog(ctx, "build", 1, GrepBuildLogToolArgs{MaxMatches: 5})
			if err != nil || grep.TotalMatches != 1 || grep.Matches[0].Line != 2 || grep.Matches[0].Offset != 2 {
				t.Fatalf("grep=%+v err=%v", grep, err)
			}
			if n := f.count("GET /job/build/1/logText/progressiveText"); n != 1 {
				t.Errorf("finished log was fetched %d times, want 1 (memory fallback)", n)
			}
			if entries, _ := os.ReadDir(sharedFallback); len(entries) != 0 {
				t.Errorf("fallback directory accessible to others was used: %v", entries)
			}
			// Downloading falls back to a temporary file ...
			dl, err := opts.downloadBuildLog(ctx, "build", 1, "")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(dl.Path)
			if data, _ := os.ReadFile(dl.Path); string(data) != "a\nerror: b\nc\n" || dl.Lines != 3 || dl.Size != 13 {
				t.Errorf("download=%+v", dl)
			}
			// ... and reports a usable error for an unwritable explicit path.
			if _, err := opts.downloadBuildLog(ctx, "build", 1, filepath.Join(blocker, "x.log")); err == nil || !strings.Contains(err.Error(), "output=text") {
				t.Errorf("expected write error with hint, got %v", err)
			}
		})
	}
}

func TestLogCacheFallsBackToPrivateTempDir(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(t.TempDir(), "private")
	f, opts := newFakeJenkins(t)
	f.handle("GET /job/build/1/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
		writeMultipartLog(w, "a\nb\n", 0, 4, true)
	})
	// Each store stands for a separate server process (CLI use spawns one per call).
	for range 2 {
		opts.Logs = newLogStore(filepath.Join(blocker, "cache"), fallback, opts.URL)
		snap, err := opts.getLog(context.Background(), "build", 1)
		if err != nil || string(snap.Data) != "a\nb\n" || !strings.HasPrefix(snap.Path, fallback+string(filepath.Separator)) {
			t.Fatalf("data=%q path=%q err=%v", snap.Data, snap.Path, err)
		}
	}
	if n := f.count("GET /job/build/1/logText/progressiveText"); n != 1 {
		t.Errorf("log was fetched %d times, want 1 (fallback cache)", n)
	}
	if info, err := os.Stat(fallback); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("fallback directory must be private: %v %v", info, err)
	}
}

func TestDownloadBuildLogToPathAndCache(t *testing.T) {
	f, opts := newFakeJenkins(t)
	f.handle("GET /job/build/1/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
		writeMultipartLog(w, "x\ny\n", 0, 4, true)
	})
	dest := filepath.Join(t.TempDir(), "sub", "build.log")
	dl, err := opts.downloadBuildLog(context.Background(), "build", 1, dest)
	if err != nil || dl.Path != dest {
		t.Fatalf("dl=%+v err=%v", dl, err)
	}
	if data, _ := os.ReadFile(dest); string(data) != "x\ny\n" {
		t.Errorf("unexpected file content %q", data)
	}
	dl, err = opts.downloadBuildLog(context.Background(), "build", 1, "")
	if err != nil || dl.Path != opts.Logs.cachePaths("build", 1)[0] {
		t.Errorf("dl=%+v err=%v", dl, err)
	}
}

func TestCachePathCannotEscapeCacheDir(t *testing.T) {
	s := newLogStore("/cache", "", "https://jenkins.example.com:8443/ci/")
	for _, job := range []string{"../../etc", "a/../../b", "..", "a/./b"} {
		p := s.cachePaths(job, 1)[0]
		if !strings.HasPrefix(p, "/cache/jenkins.example.com_8443_ci/") || strings.Contains(p, "/../") {
			t.Errorf("job %q maps to %q", job, p)
		}
	}
}

func TestGetLogUnknownBuild(t *testing.T) {
	_, opts := newFakeJenkins(t)
	if _, err := opts.getLog(context.Background(), "build", 99); err == nil || !strings.Contains(err.Error(), "build #99 not found") {
		t.Errorf("expected not-found error, got %v", err)
	}
	if len(opts.Logs.mem) != 0 {
		t.Errorf("failed fetch left %d entries in memory", len(opts.Logs.mem))
	}
}

func TestMemoryLogsAreBounded(t *testing.T) {
	f, opts := newFakeJenkins(t)
	for i := 1; i <= maxMemoryLogs+5; i++ {
		f.handle("GET /job/build/"+strconv.Itoa(i)+"/logText/progressiveText", func(w http.ResponseWriter, r *http.Request) {
			writeMultipartLog(w, "running\n", 0, 8, false)
		})
		if _, err := opts.getLog(context.Background(), "build", i); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(opts.Logs.mem); n != maxMemoryLogs {
		t.Errorf("%d logs kept in memory, want %d", n, maxMemoryLogs)
	}
}
