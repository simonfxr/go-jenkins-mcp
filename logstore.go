package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	logCacheMaxAge   = 30 * 24 * time.Hour
	maxMemoryLogs    = 8
	logFileExtension = ".log"
)

var (
	// Jenkins embeds serialized ConsoleNote objects in logs as
	// ESC[8mha:<base64>ESC[0m; they are invisible in the UI and pure noise here.
	consoleNoteRe = regexp.MustCompile(`\x1b\[8mha:.*?\x1b\[0m`)
	// ANSI escape sequences: CSI, OSC and two-character escapes.
	ansiRe = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\^_])`)
)

// cleanLogLine normalizes one log line (without its line terminator): console
// notes and ANSI escapes are removed and carriage-return overwrites (progress
// bars) are collapsed to their final state.
func cleanLogLine(line []byte) []byte {
	line = bytes.TrimRight(line, "\r")
	if bytes.IndexByte(line, 0x1b) >= 0 {
		line = consoleNoteRe.ReplaceAll(line, nil)
		line = ansiRe.ReplaceAll(line, nil)
	}
	if i := bytes.LastIndexByte(line, '\r'); i >= 0 {
		line = line[i+1:]
	}
	return line
}

// cleanLog copies r to w line by line through cleanLogLine, using LF line endings.
func cleanLog(w *bytes.Buffer, r io.Reader) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			terminated := line[len(line)-1] == '\n'
			if terminated {
				line = line[:len(line)-1]
			}
			w.Write(cleanLogLine(line))
			if terminated {
				w.WriteByte('\n')
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// logChunk is a cleaned piece of a build log starting at raw offset start.
type logChunk struct {
	text     []byte
	start    int64 // raw offset the chunk actually starts at
	end      int64 // raw offset to continue from
	complete bool  // no more output will follow
}

// fetchLog downloads the build log from raw offset start. It asks for Jenkins'
// multipart progressive-text mode, which strips console notes server-side and
// reports exact resume offsets; older versions ignore the Accept header and
// answer with plain text plus X-Text-Size/X-More-Data headers.
func (opts *JenkinsOptions) fetchLog(ctx context.Context, jobName string, buildNumber int, start int64) (*logChunk, error) {
	apiPath := fmt.Sprintf("%s/%d/logText/progressiveText?start=%d", buildJobPath(jobName), buildNumber, start)
	resp, err := opts.request(ctx, opts.LogsClient, http.MethodGet, apiPath, nil, map[string]string{"Accept": "multipart/form-data"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job %q build #%d not found", jobName, buildNumber)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError(resp)
	}

	var buf bytes.Buffer
	mediaType, params, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(mediaType, "multipart/") && params["boundary"] != "" {
		var meta *struct {
			Start     int64 `json:"start"`
			End       int64 `json:"end"`
			Completed bool  `json:"completed"`
		}
		mr := multipart.NewReader(resp.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read log response: %w", err)
			}
			switch part.FormName() {
			case "text":
				if err := cleanLog(&buf, part); err != nil {
					return nil, fmt.Errorf("failed to read log response: %w", err)
				}
			case "meta":
				if err := json.NewDecoder(part).Decode(&meta); err != nil {
					return nil, fmt.Errorf("failed to decode log metadata: %w", err)
				}
			}
		}
		if meta == nil {
			return nil, fmt.Errorf("incomplete log response from jenkins (missing metadata)")
		}
		return &logChunk{text: buf.Bytes(), start: meta.Start, end: meta.End, complete: meta.Completed}, nil
	}

	counter := &countingReader{r: resp.Body}
	if err := cleanLog(&buf, counter); err != nil {
		return nil, fmt.Errorf("failed to read log response: %w", err)
	}
	chunk := &logChunk{text: buf.Bytes(), start: start, end: start + counter.n, complete: resp.Header.Get("X-More-Data") != "true"}
	if size, err := strconv.ParseInt(resp.Header.Get("X-Text-Size"), 10, 64); err == nil {
		chunk.end = size
		if size < start {
			chunk.start = 0 // log was rolled over and sent in full
		}
	}
	return chunk, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// logSnapshot is a consistent view of a cleaned build log.
type logSnapshot struct {
	Data     []byte
	Complete bool   // the build finished writing its log
	Path     string // on-disk cache file holding Data, if any
}

// memLog is the in-memory state of a log that is still growing, or of a
// finished log that could not be written to disk.
type memLog struct {
	mu           sync.Mutex
	data         []byte
	cursor       int64
	complete     bool
	persistTried bool
	lastUsed     time.Time
}

// logStore mirrors cleaned build logs. Finished logs are immutable and cached
// on disk; logs of running builds are kept in memory and extended
// incrementally.
//
// The cache must never be a reason for a tool call to fail: when the cache
// directory is unusable (read-only filesystem, sandbox) a private directory
// below the temporary directory is tried, and if that fails too everything
// transparently stays in memory.
type logStore struct {
	dirs         []string // candidate cache directories in order of preference; empty disables the disk cache
	fallbackBase string   // private temporary directory that dirs[1] lives in

	mu        sync.Mutex
	mem       map[string]*memLog
	badDirs   map[string]bool // directories that failed to take a write
	warned    bool
	pruneOnce sync.Once
}

// newLogStore creates a log store caching below cacheDir, with fallbackBase as
// second choice. Empty values disable the respective location.
func newLogStore(cacheDir, fallbackBase, jenkinsURL string) *logStore {
	s := &logStore{mem: map[string]*memLog{}, badDirs: map[string]bool{}}
	if cacheDir == "" {
		return s
	}
	host := "jenkins"
	if u, err := url.Parse(jenkinsURL); err == nil && u.Host != "" {
		host = u.Host + strings.ReplaceAll(strings.TrimRight(u.Path, "/"), "/", "_")
	}
	host = safePathSegment(host)
	s.dirs = []string{filepath.Join(cacheDir, host)}
	if fallbackBase != "" {
		s.fallbackBase = fallbackBase
		s.dirs = append(s.dirs, filepath.Join(fallbackBase, host))
	}
	return s
}

// defaultFallbackCacheDir is the per-user cache location below the temporary directory.
func defaultFallbackCacheDir() string {
	return filepath.Join(os.TempDir(), "go-jenkins-mcp-"+strconv.Itoa(os.Getuid()))
}

// usable reports whether cache directory i may be used. Temporary directories
// are shared between users, so the fallback is only trusted if it is a real
// directory (not a symlink) that nobody else can access.
func (s *logStore) usable(i int, create bool) bool {
	if i == 0 {
		return true
	}
	if create {
		_ = os.Mkdir(s.fallbackBase, 0o700)
	}
	info, err := os.Lstat(s.fallbackBase)
	return err == nil && info.IsDir() && info.Mode().Perm()&0o077 == 0
}

// safePathSegment makes s usable as a single file name.
func safePathSegment(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', 0:
			return '_'
		}
		return r
	}, s)
	if s == "" || s == "." || s == ".." {
		return "_" + s
	}
	return s
}

// cachePaths returns the candidate cache files for a build log.
func (s *logStore) cachePaths(jobName string, buildNumber int) []string {
	var rel []string
	for seg := range strings.SplitSeq(jobName, "/") {
		if seg != "" {
			rel = append(rel, safePathSegment(seg))
		}
	}
	rel = append(rel, strconv.Itoa(buildNumber)+logFileExtension)
	paths := make([]string, 0, len(s.dirs))
	for _, dir := range s.dirs {
		paths = append(paths, filepath.Join(append([]string{dir}, rel...)...))
	}
	return paths
}

// load returns a finished log from the disk cache.
func (s *logStore) load(jobName string, buildNumber int) (data []byte, path string, ok bool) {
	for i, p := range s.cachePaths(jobName, buildNumber) {
		if !s.usable(i, false) {
			continue
		}
		if data, err := os.ReadFile(p); err == nil {
			return data, p, true
		}
	}
	return nil, "", false
}

// persist atomically writes a finished log to the first cache directory that
// accepts it. Directories that failed once are not tried again.
func (s *logStore) persist(jobName string, buildNumber int, data []byte) (string, error) {
	err := fmt.Errorf("log cache disabled")
	for i, path := range s.cachePaths(jobName, buildNumber) {
		dir := s.dirs[i]
		s.mu.Lock()
		bad := s.badDirs[dir]
		s.mu.Unlock()
		if bad || !s.usable(i, true) {
			continue
		}
		if werr := writeFileAtomic(path, data); werr != nil {
			err = werr
			s.mu.Lock()
			s.badDirs[dir] = true
			s.mu.Unlock()
			log.Printf("log cache directory %s unusable: %v", dir, werr)
			continue
		}
		s.pruneOnce.Do(func() { go s.prune(dir) })
		return path, nil
	}
	return "", err
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// prune removes cached logs that were not written for a long time.
func (s *logStore) prune(dir string) {
	cutoff := time.Now().Add(-logCacheMaxAge)
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, logFileExtension) && !strings.HasPrefix(name, ".tmp-") {
			return nil
		}
		if info, err := d.Info(); err == nil && info.ModTime().Before(cutoff) {
			os.Remove(path)
		}
		return nil
	})
}

func (s *logStore) warnOnce(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.warned && len(s.dirs) > 0 {
		s.warned = true
		log.Printf("log cache unavailable, keeping build logs in memory: %v", err)
	}
}

// entry returns the in-memory state for a build log, creating it if needed and
// evicting the least recently used entries beyond the limit.
func (s *logStore) entry(key string) *memLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.mem[key]
	if e == nil {
		e = &memLog{}
		s.mem[key] = e
	}
	e.lastUsed = time.Now()
	for len(s.mem) > maxMemoryLogs {
		oldestKey := ""
		var oldest time.Time
		for k, v := range s.mem {
			if k != key && (oldestKey == "" || v.lastUsed.Before(oldest)) {
				oldestKey, oldest = k, v.lastUsed
			}
		}
		delete(s.mem, oldestKey)
	}
	return e
}

func (s *logStore) drop(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.mem, key)
}

// getLog returns the cleaned log of a build, fetching whatever is new.
func (opts *JenkinsOptions) getLog(ctx context.Context, jobName string, buildNumber int) (*logSnapshot, error) {
	s := opts.Logs
	if data, path, ok := s.load(jobName, buildNumber); ok {
		return &logSnapshot{Data: data, Complete: true, Path: path}, nil
	}

	key := jobName + "#" + strconv.Itoa(buildNumber)
	e := s.entry(key)
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.complete {
		chunk, err := opts.fetchLog(ctx, jobName, buildNumber, e.cursor)
		if err != nil {
			if e.cursor == 0 {
				s.drop(key)
			}
			return nil, err
		}
		if chunk.start != e.cursor {
			e.data = nil // Jenkins restarted the log from the beginning
		}
		e.data = append(e.data, chunk.text...)
		e.cursor = chunk.end
		e.complete = chunk.complete
	}
	// Later appends write beyond the snapshot's length and never into it.
	snap := &logSnapshot{Data: e.data[:len(e.data):len(e.data)], Complete: e.complete}
	if e.complete && !e.persistTried {
		e.persistTried = true
		if path, err := s.persist(jobName, buildNumber, e.data); err != nil {
			s.warnOnce(err)
		} else {
			snap.Path = path
			s.drop(key)
		}
	}
	return snap, nil
}
