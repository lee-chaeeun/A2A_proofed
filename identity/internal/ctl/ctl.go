// Package ctl is the client for the independent controller: every component posts
// events; the controller tags them with the current cell and persists them.
package ctl

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

type Event struct {
	TS     string         `json:"ts"`
	Cell   string         `json:"cell,omitempty"`
	Source string         `json:"source"`
	Kind   string         `json:"kind"`
	Data   map[string]any `json:"data,omitempty"`
}

type Client struct {
	URL    string
	Source string
	HTTP   *http.Client
	// Failed counts emissions the controller did not acknowledge; telemetry
	// completeness checks read it so a silent drop is never mistaken for "no event".
	Failed int64
}

// Nop returns a client that records nothing (unit tests, offline reverification).
func Nop() *Client { return &Client{} }

func New(url, source string) *Client {
	return &Client{URL: url, Source: source, HTTP: &http.Client{Timeout: 3 * time.Second}}
}

// Emit posts an event; failures are ignored so the controller never changes
// protocol behaviour.
func (c *Client) Emit(kind string, data map[string]any) {
	if c == nil || c.URL == "" {
		return
	}
	ev := Event{TS: time.Now().UTC().Format(time.RFC3339Nano), Source: c.Source, Kind: kind, Data: data}
	b, _ := json.Marshal(ev)
	resp, err := c.HTTP.Post(c.URL+"/event", "application/json", bytes.NewReader(b))
	if err != nil || resp.StatusCode >= 300 {
		atomic.AddInt64(&c.Failed, 1)
	}
	if err == nil {
		resp.Body.Close()
	}
}

func (c *Client) post(path string, v any) error {
	b, _ := json.Marshal(v)
	resp, err := c.HTTP.Post(c.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// SetCell tells the controller which matrix cell is running and where to write.
func (c *Client) SetCell(cell, outDir string) error {
	return c.post("/cell", map[string]string{"cell": cell, "out_dir": outDir})
}

// Events fetches events recorded for a cell.
func (c *Client) Events(cell string) ([]Event, error) {
	resp, err := c.HTTP.Get(c.URL + "/events?cell=" + url.QueryEscape(cell))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var evs []Event
	return evs, json.NewDecoder(resp.Body).Decode(&evs)
}
