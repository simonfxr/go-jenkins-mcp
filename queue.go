package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const queueItemTree = "id,task[name,url],why,inQueueSince,stuck,params,cancelled,executable[" + buildTree + "]"

type queueItemWire struct {
	ID   int `json:"id"`
	Task struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"task"`
	Why          string     `json:"why"`
	InQueueSince int64      `json:"inQueueSince"`
	Stuck        bool       `json:"stuck"`
	Params       string     `json:"params"`
	Cancelled    bool       `json:"cancelled"`
	Executable   *buildWire `json:"executable"`
}

func (w *queueItemWire) jobName() string {
	if job, _, ok := parseJobURL(w.Task.URL); ok {
		return job
	}
	return w.Task.Name
}

func (w *queueItemWire) toQueueItem() *QueueItem {
	item := &QueueItem{
		QueueID:     w.ID,
		JobName:     w.jobName(),
		URL:         w.Task.URL,
		Status:      "queued",
		Why:         w.Why,
		QueuedSince: msTime(w.InQueueSince),
		Stuck:       w.Stuck,
		Parameters:  strings.TrimSpace(w.Params),
	}
	switch {
	case w.Cancelled:
		item.Status = "cancelled"
	case w.Executable != nil && w.Executable.Number > 0:
		b := w.Executable.toBuild()
		item.Build = &b
		item.Status = "started"
	}
	return item
}

// extractQueueID extracts the queue item ID from a queue item URL.
func extractQueueID(queueURL string) int {
	if i := strings.IndexAny(queueURL, "?#"); i >= 0 {
		queueURL = queueURL[:i]
	}
	parts := strings.Split(strings.TrimSuffix(queueURL, "/"), "/")
	queueID, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return 0
	}
	return queueID
}

// getQueueItem fetches a queue item by ID. Jenkins forgets queue items five
// minutes after they left the queue; when jobName is known the build is then
// located through its recorded queue ID instead.
func (opts *JenkinsOptions) getQueueItem(ctx context.Context, queueID int, jobName string) (*QueueItem, error) {
	var w queueItemWire
	err := opts.getJSON(ctx, fmt.Sprintf("/queue/item/%d/api/json?tree=%s", queueID, queueItemTree), &w)
	if err == nil {
		return w.toQueueItem(), nil
	}
	if !isNotFound(err) {
		return nil, err
	}
	if jobName == "" {
		return nil, fmt.Errorf("queue item #%d not found: Jenkins forgets queue items 5 minutes after they leave the queue; pass job_name to look up the resulting build", queueID)
	}
	var data struct {
		URL    string      `json:"url"`
		Builds []buildWire `json:"allBuilds"`
	}
	apiPath := buildJobPath(jobName) + "/api/json?tree=url,allBuilds[queueId," + buildTree + "]{0,50}"
	if err := opts.getJSON(ctx, apiPath, &data); err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("job %q not found", jobName)
		}
		return nil, err
	}
	for i := range data.Builds {
		if data.Builds[i].QueueID == queueID {
			b := data.Builds[i].toBuild()
			return &QueueItem{QueueID: queueID, JobName: jobName, URL: data.URL, Status: "started", Build: &b}, nil
		}
	}
	return nil, fmt.Errorf("queue item #%d not found and no recent build of job %q originates from it (it was probably cancelled)", queueID, jobName)
}

// getQueuedBuilds fetches queued builds from the Jenkins queue.
func (opts *JenkinsOptions) getQueuedBuilds(ctx context.Context) ([]QueuedBuild, error) {
	var data struct {
		Items []queueItemWire `json:"items"`
	}
	if err := opts.getJSON(ctx, "/queue/api/json?tree=items[id,task[name,url],why,inQueueSince,stuck,params]", &data); err != nil {
		return nil, err
	}
	queued := make([]QueuedBuild, 0, len(data.Items))
	for i := range data.Items {
		it := &data.Items[i]
		queued = append(queued, QueuedBuild{
			JobName:     it.jobName(),
			URL:         it.Task.URL,
			QueueID:     it.ID,
			Why:         it.Why,
			QueuedSince: msTime(it.InQueueSince),
			Stuck:       it.Stuck,
			Parameters:  strings.TrimSpace(it.Params),
		})
	}
	return queued, nil
}

// waitForQueueItem polls a queue item until it started, was cancelled or the
// timeout expired. With a zero timeout the current state is returned.
func (opts *JenkinsOptions) waitForQueueItem(ctx context.Context, queueID int, jobName string, timeout time.Duration, progress progressFunc) (*WaitForQueueItemToolResponse, error) {
	start := time.Now()
	deadline := start.Add(timeout)
	interval := min(opts.PollInterval, time.Second)
	failures := 0
	var last *QueueItem
	for {
		item, err := opts.getQueueItem(ctx, queueID, jobName)
		switch {
		case err == nil:
			failures = 0
			last = item
			if item.Status != "queued" {
				return &WaitForQueueItemToolResponse{QueueItem: item, Build: item.Build, Status: item.Status, WaitTime: DurationMS(time.Since(start))}, nil
			}
			progress("queued: " + item.Why)
		case ctx.Err() != nil:
			return nil, ctx.Err()
		default:
			// Missing items and persistent errors are reported instead of waiting out the timeout.
			failures++
			if last == nil || failures >= maxPollFailures || strings.Contains(err.Error(), "not found") {
				return nil, err
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return &WaitForQueueItemToolResponse{QueueItem: last, Status: "queued", TimedOut: true, WaitTime: DurationMS(time.Since(start))}, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(min(interval, remaining)):
		}
		interval = min(interval*2, opts.PollInterval)
	}
}

// cancelQueueItem cancels a queued build. It returns false when the item is no
// longer in the queue.
func (opts *JenkinsOptions) cancelQueueItem(ctx context.Context, queueID int) (bool, error) {
	resp, err := opts.post(ctx, "/queue/cancelItem?id="+url.QueryEscape(strconv.Itoa(queueID)), nil)
	if err != nil {
		return false, fmt.Errorf("failed to cancel queue item: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode >= 400:
		return false, newAPIError(resp)
	}
	return true, nil
}
