package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Build represents a Jenkins build. Detail fields are only populated by
// jenkins_get_build.
type Build struct {
	Number            int        `json:"number"`
	URL               string     `json:"url,omitempty"`
	DisplayName       string     `json:"displayName,omitempty"` // omitted when it is just "#<number>"
	Building          bool       `json:"building"`
	Result            string     `json:"result,omitempty"` // SUCCESS, FAILURE, UNSTABLE, ABORTED, NOT_BUILT; empty while building
	Timestamp         TimeMS     `json:"timestamp"`
	Duration          DurationMS `json:"duration"` // elapsed time so far while building
	EstimatedDuration DurationMS `json:"estimatedDuration,omitzero"`

	// Parameters holds all build parameters (jenkins_get_build).
	Parameters map[string]string `json:"parameters,omitempty"`
	// NonDefaultParameters holds only parameters whose value differs from the
	// job's current default (build listings).
	NonDefaultParameters map[string]string `json:"nonDefaultParameters,omitempty"`

	Description   string        `json:"description,omitempty"`
	QueueID       int           `json:"queueId,omitempty"`
	BuiltOn       string        `json:"builtOn,omitempty"`
	Causes        []string      `json:"causes,omitempty"`
	Changes       []BuildChange `json:"changes,omitempty"`
	ChangeCount   int           `json:"changeCount,omitempty"`
	Artifacts     []string      `json:"artifacts,omitempty"`     // relative paths, usable with jenkins_download_artifact
	ArtifactCount int           `json:"artifactCount,omitempty"` // total number (matching artifact_filter), when not all are listed

	inProgress bool // true until the build is fully finished (including post-production)
}

// BuildChange is one SCM change included in a build.
type BuildChange struct {
	Commit  string `json:"commit,omitempty"`
	Author  string `json:"author,omitempty"`
	Message string `json:"message"`
}

// BuildParameter represents a Jenkins build parameter definition.
type BuildParameter struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Description  string   `json:"description,omitempty"`
	DefaultValue any      `json:"defaultValue"`
	Choices      []string `json:"choices,omitempty"` // For choice parameters
}

// Job represents a Jenkins job with its current status.
type Job struct {
	Name         string           `json:"name"` // full path, e.g. "folder/job"
	URL          string           `json:"url"`
	Type         string           `json:"type,omitempty"`  // "folder" for folders
	Color        string           `json:"color,omitempty"` // Jenkins color coding (blue, red, yellow, ..., *_anime while building)
	Buildable    bool             `json:"buildable"`
	InQueue      bool             `json:"inQueue,omitempty"`
	Description  string           `json:"description,omitempty"`
	LastBuild    *Build           `json:"lastBuild,omitempty"`    // jenkins_get_jobs only
	RecentBuilds []Build          `json:"recentBuilds,omitempty"` // newest first
	Parameters   []BuildParameter `json:"parameters,omitempty"`   // parameter definitions
	QueuedBuilds []QueuedBuild    `json:"queuedBuilds,omitempty"` // queued builds for this job
}

// RunningBuild represents a currently running Jenkins build.
type RunningBuild struct {
	JobName     string     `json:"jobName"`
	BuildNumber int        `json:"buildNumber"`
	URL         string     `json:"url"`
	Node        string     `json:"node,omitempty"`
	StartTime   TimeMS     `json:"startTime"`
	Duration    DurationMS `json:"duration"`
	Progress    *int       `json:"progress,omitempty"` // percent of estimated duration
	LikelyStuck bool       `json:"likelyStuck,omitempty"`
}

// QueuedBuild represents a queued Jenkins build item.
type QueuedBuild struct {
	JobName     string `json:"jobName"`
	URL         string `json:"url"`
	QueueID     int    `json:"queueId"`
	Why         string `json:"why"`
	QueuedSince TimeMS `json:"queuedSince"`
	Stuck       bool   `json:"stuck,omitempty"`
	Parameters  string `json:"parameters,omitempty"`
}

// QueueItem represents a Jenkins queue item.
type QueueItem struct {
	QueueID     int    `json:"queueId"`
	JobName     string `json:"jobName,omitempty"`
	URL         string `json:"url,omitempty"`
	Status      string `json:"status"` // queued, started, cancelled
	Why         string `json:"why,omitempty"`
	QueuedSince TimeMS `json:"queuedSince,omitzero"`
	Stuck       bool   `json:"stuck,omitempty"`
	Parameters  string `json:"parameters,omitempty"`
	Build       *Build `json:"build,omitempty"` // assigned build once started
}

// Node describes a Jenkins agent/controller node.
type Node struct {
	Name          string   `json:"name"`
	Online        bool     `json:"online"`
	Executors     int      `json:"executors"`
	BusyExecutors int      `json:"busyExecutors"`
	Labels        []string `json:"labels,omitempty"`
	OfflineReason string   `json:"offlineReason,omitempty"`
}

// DurationMS is a JSON-friendly duration that unmarshals from milliseconds (number)
// and marshals to a human-readable string (e.g., "5m10s").
type DurationMS time.Duration

// UnmarshalJSON parses a duration from milliseconds or string into DurationMS.
func (d *DurationMS) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*d = 0
		return nil
	}
	var ms int64
	if err := json.Unmarshal(b, &ms); err == nil {
		*d = DurationMS(time.Duration(ms) * time.Millisecond)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if dur, err := time.ParseDuration(s); err == nil {
			*d = DurationMS(dur)
			return nil
		}
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			*d = DurationMS(time.Duration(v) * time.Millisecond)
			return nil
		}
	}
	return fmt.Errorf("invalid duration value: %s", string(b))
}

// MarshalJSON encodes DurationMS as a human-readable string (e.g., "5m10s").
// Durations of a second or more are rounded to whole seconds.
func (d DurationMS) MarshalJSON() ([]byte, error) {
	dur := time.Duration(d)
	if dur >= time.Second {
		dur = dur.Round(time.Second)
	}
	return json.Marshal(dur.String())
}

// IsZero supports the omitzero JSON option.
func (d DurationMS) IsZero() bool { return d <= 0 }

func msDuration(ms int64) DurationMS { return DurationMS(time.Duration(ms) * time.Millisecond) }

// TimeMS is a JSON-friendly time that unmarshals from milliseconds-since-epoch (number)
// and marshals to an RFC3339 timestamp string (UTC).
type TimeMS time.Time

// UnmarshalJSON parses a timestamp from milliseconds or RFC3339 string into TimeMS.
func (t *TimeMS) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*t = TimeMS(time.Time{})
		return nil
	}
	var ms int64
	if err := json.Unmarshal(b, &ms); err == nil {
		*t = msTime(ms)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			*t = TimeMS(time.Time{})
			return nil
		}
		if parsed, err := time.Parse(time.RFC3339Nano, s); err == nil {
			*t = TimeMS(parsed)
			return nil
		}
		if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
			*t = msTime(ms)
			return nil
		}
	}
	return fmt.Errorf("invalid timestamp value: %s", string(b))
}

// MarshalJSON encodes TimeMS as an RFC3339 UTC timestamp string.
func (t TimeMS) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(tt.UTC().Format(time.RFC3339))
}

// IsZero supports the omitzero JSON option.
func (t TimeMS) IsZero() bool { return time.Time(t).IsZero() }

func msTime(ms int64) TimeMS {
	if ms <= 0 {
		return TimeMS(time.Time{})
	}
	return TimeMS(time.UnixMilli(ms))
}
