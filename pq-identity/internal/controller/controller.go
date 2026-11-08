// Package controller is the independent observer. It records who served which
// exchange, which process invoked which signer (reported by the gate), and where
// each job token landed. It has no role in any verification decision.
package controller

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"a2aid/internal/ctl"
)

type Controller struct {
	mu     sync.Mutex
	cell   string
	outDir string
	events map[string][]ctl.Event
	files  map[string]*os.File
}

func New() *Controller {
	return &Controller{events: map[string][]ctl.Event{}, files: map[string]*os.File{}}
}

func (c *Controller) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /event", func(w http.ResponseWriter, r *http.Request) {
		var ev ctl.Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if ev.TS == "" {
			ev.TS = time.Now().UTC().Format(time.RFC3339Nano)
		}
		ev.Cell = c.cell
		c.events[c.cell] = append(c.events[c.cell], ev)
		if f := c.files[c.cell]; f != nil {
			b, _ := json.Marshal(ev)
			f.Write(append(b, '\n'))
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /cell", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Cell, OutDir string }
		var raw map[string]string
		json.NewDecoder(r.Body).Decode(&raw)
		req.Cell, req.OutDir = raw["cell"], raw["out_dir"]
		c.mu.Lock()
		defer c.mu.Unlock()
		c.cell = req.Cell
		c.outDir = req.OutDir
		if req.OutDir != "" {
			os.MkdirAll(req.OutDir, 0o755)
			f, err := os.OpenFile(filepath.Join(req.OutDir, "controller-events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err == nil {
				c.files[req.Cell] = f
			}
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		cell := r.URL.Query().Get("cell")
		c.mu.Lock()
		evs := append([]ctl.Event(nil), c.events[cell]...)
		c.mu.Unlock()
		if evs == nil {
			evs = []ctl.Event{}
		}
		json.NewEncoder(w).Encode(evs)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	return mux
}
