package matrix

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"a2aid/internal/ctl"
	"a2aid/internal/pqdev"
	"a2aid/internal/registry"
	"a2aid/internal/tpmsig"
	"a2aid/internal/verifier"
	"a2aid/internal/wire"
)

// Manifest is the pre-run, frozen description of fixtures and expected outcomes.
type Manifest struct {
	Version    int       `json:"version"`
	FrozenAt   string    `json:"frozen_at"`
	Note       string    `json:"note,omitempty"`
	Policies   []string  `json:"policies"`
	Fixtures   []Fixture `json:"fixtures"`
	RaceTrials *RaceSpec `json:"race_trials,omitempty"`
}

type Fixture struct {
	ID                string            `json:"id"`
	Title             string            `json:"title"`
	Endpoint          string            `json:"endpoint"` // A | B | A-hijacked | B-then-A | A-and-B
	Capabilities      []string          `json:"capabilities"`
	Permissions       string            `json:"permissions"`
	Expected          map[string]string `json:"expected"`
	ExpectedRecipient string            `json:"expected_recipient"`
	// Manifest version >= 4: explicit classification and a
	// per-policy expected recipient, so "accept" is never read as "delivered to A".
	Class                     string            `json:"class,omitempty"` // honest | malicious | ablation
	ExpectedRecipientByPolicy map[string]string `json:"expected_recipient_by_policy,omitempty"`
	PolicyClasses             map[string]string `json:"policy_classes,omitempty"` // ablation | secured-baseline | defended
}

// class returns the explicit fixture class, or a derivation for older manifests
// (endpoint A = honest; anything else = malicious), labelled as derived.
func (fx Fixture) class() (string, bool) {
	if fx.Class != "" {
		return fx.Class, true
	}
	if fx.Endpoint == "A" {
		return "honest", false
	}
	return "malicious", false
}

type RaceSpec struct {
	Policies   []string `json:"policies"`
	Count      int      `json:"count"`
	SeedBase   int64    `json:"seed_base"`
	MaxDelayMs int      `json:"max_delay_ms"`
}

// Appraisal is one requester decision (one row of appraisals.csv). Everything the
// requester concluded plus the controller's typed ground truth for that decision.
type Appraisal struct {
	Cell                string   `json:"cell"`
	Fixture             string   `json:"fixture"`
	Policy              string   `json:"policy"`
	Index               int      `json:"appraisal_index"`
	ExpectedIdentity    string   `json:"expected_identity"`
	Capabilities        []string `json:"attacker_capabilities"`
	EndpointURL         string   `json:"endpoint_url"`
	EndpointContacted   string   `json:"endpoint_contacted"` // controller truth, from exchange_served/job_received
	EndpointEqual       string   `json:"endpoint_equal"`
	TLSAuthenticated    string   `json:"tls_authenticated"`
	TLSPeerName         string   `json:"tls_peer_name"`
	TLSNameMatch        string   `json:"tls_name_match"`
	CBMatched           string   `json:"cb_matched"`
	CardVerdict         string   `json:"card_verdict"`
	SessionVerdict      string   `json:"session_verdict"`
	NonceVerdict        string   `json:"nonce_verdict"`
	SigVerdict          string   `json:"sig_verdict"`
	QuoteVerdict        string   `json:"quote_verdict"`
	EnvelopeVerdict     string   `json:"envelope_verdict"`
	InnerQuoteValid     string   `json:"inner_quote_valid"`
	CryptoAccept        bool     `json:"crypto_accept"`
	Accept              bool     `json:"accept"`
	FailureStage        string   `json:"failure_stage"`
	Code                string   `json:"code"`
	Reason              string   `json:"reason"`
	DispatchAttempted   bool     `json:"dispatch_attempted"`
	JobToken            string   `json:"job_token"`
	ObservedRecipient   string   `json:"observed_recipient"` // from job_received(token), typed
	AckReceived         bool     `json:"ack_received"`
	AckDeployment       string   `json:"ack_claimed_deployment"`
	Executed            string   `json:"executed"` // "n/a (no execution implemented)" always
	PCRAtReceipt        string   `json:"pcr_at_receipt_hex"`
	ConfigChanged       string   `json:"config_changed_before_delivery"`
	UnauthorizedRecip   bool     `json:"unauthorized_recipient_access"`
	LegitimateRejection bool     `json:"legitimate_rejection"`
	KeysUsed            []string `json:"keys_used"`          // typed: owner label of every enrolled key that signed in this cell
	Invokers            []string `json:"invokers"`           // typed: gate peer labels / in-process signers
	Materials           []string `json:"materials"`          // own / copied-volume / ...
	SignerOK            string   `json:"signer_attribution"` // correct | false-attribution | n/a
	CustodyBroken       bool     `json:"custody_broken"`
	Telemetry           string   `json:"telemetry"` // complete | missing: ...
	// Release evidence (requester-observed; joined with the recipient's receipt)
	DecisionID           string `json:"decision_id"`
	JobSent              bool   `json:"job_sent"`                    // request written to the transport (not wire proof)
	JobConnReused        bool   `json:"job_reused_proof_connection"` // dispatch stayed on the pinned proof connection
	PinnedConnID         int    `json:"pinned_conn_id"`
	DispatchConnID       int    `json:"dispatch_conn_id"`
	DispatchOutcome      string `json:"dispatch_outcome"`          // none | acked | refused_reconnect | refused_dispatch | unknown_outcome | error
	ReceiptExporterMatch string `json:"receipt_exporter_match"`    // yes | no | n/a (recipient's exporter == requester's pinned connection exporter)
	ReceiptDecisionID    string `json:"receipt_decision_id_match"` // yes | no | n/a
}

// Row is one matrix cell (CSV/JSONL output), aggregating its appraisals.
type Row struct {
	Cell              string   `json:"cell"`
	Fixture           string   `json:"fixture"`
	FixtureTitle      string   `json:"fixture_title"`
	Policy            string   `json:"policy"`
	Capabilities      []string `json:"attacker_capabilities"`
	Appraisals        int      `json:"appraisals"`
	EndpointContacted string   `json:"endpoint_contacted"`
	Decision          string   `json:"decision"`
	JobRecipients     string   `json:"job_recipients"`
	Releases          int      `json:"releases"`
	Receipts          int      `json:"receipts"`
	DuplicateDispatch bool     `json:"duplicate_dispatch"`
	DuplicateReceipt  bool     `json:"duplicate_receipt"`
	FailureStage      string   `json:"failure_stage"`
	Code              string   `json:"code"`
	Reason            string   `json:"reason"`
	ExpectedResult    string   `json:"expected_result"`
	ObservedResult    string   `json:"observed_result"`
	Match             bool     `json:"match"`
	Notes             []string `json:"notes,omitempty"`
	// Decision and recipient are predicted and matched separately.
	Class             string `json:"class,omitempty"`
	ExpectedRecipient string `json:"expected_recipient,omitempty"`
	DecisionMatch     bool   `json:"decision_match"`
	RecipientMatch    bool   `json:"recipient_match"`
	RecipientChecked  bool   `json:"recipient_checked"` // false for manifests without a per-policy recipient
}

// RunOptions parameterize one matrix run (CLI and integration tests share Run).
type RunOptions struct {
	RunDir      string
	Out         string
	Fixtures    []string // empty = all
	Policies    []string // empty = manifest policies
	Manifest    string
	Predictions string
	Races       bool
	Bin         string // binary to spawn for controller/gate/agents (default: os.Executable)
	RunPathFile string // if set, the created run directory path is written here
}

func Main(args []string) {
	fs := flag.NewFlagSet("matrix", flag.ExitOnError)
	runDir := fs.String("run-dir", "run", "")
	out := fs.String("out", "results/broad", "")
	only := fs.String("fixtures", "", "comma-separated fixture IDs (default all)")
	pols := fs.String("policies", "", "comma-separated policies (default: manifest)")
	manifestPath := fs.String("manifest", "fixtures/manifest-broad.json", "")
	predictions := fs.String("predictions", "fixtures/predictions-broad.md", "")
	races := fs.Bool("races", true, "run the randomized race trials declared in the manifest")
	runPathFile := fs.String("run-path-file", "", "write the created run directory path to this file (exact handoff to callers)")
	fs.Parse(args)
	split := func(s string) []string {
		var out []string
		for _, f := range strings.Split(s, ",") {
			if f != "" {
				out = append(out, f)
			}
		}
		return out
	}
	Run(RunOptions{RunDir: *runDir, Out: *out, Fixtures: split(*only), Policies: split(*pols), Manifest: *manifestPath, Predictions: *predictions, Races: *races, RunPathFile: *runPathFile})
}

// Run executes the matrix and returns the rows, appraisals and output directory.
func Run(o RunOptions) ([]Row, []Appraisal, string) {
	abs, _ := filepath.Abs(o.RunDir)
	runID := time.Now().Format("20060102-150405")
	outDir := filepath.Join(o.Out, runID)
	os.MkdirAll(outDir, 0o755)
	bin := o.Bin
	if bin == "" {
		bin, _ = os.Executable()
	}
	reg, err := registry.Load(filepath.Join(abs, "registry.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err, "(run scripts/setup.sh first)")
		os.Exit(1)
	}
	mb, err := os.ReadFile(o.Manifest)
	if err != nil {
		panic(err)
	}
	var man Manifest
	if err := json.Unmarshal(mb, &man); err != nil {
		panic(err)
	}
	if len(o.Policies) > 0 {
		man.Policies = o.Policies
	}
	logf, _ := os.Create(filepath.Join(outDir, "run.log"))
	rt := &Runtime{RunDir: o.RunDir, AbsRun: abs, OutDir: outDir, Bin: bin, Reg: reg, HTTP: &http.Client{Timeout: 10 * time.Second}, Started: time.Now(), Log: logf}

	// Provenance before anything runs.
	src, tree := sourceHashes(".")
	prov := Provenance{RunID: runID, StartedUTC: rt.Started.UTC().Format(time.RFC3339Nano), ManifestPath: o.Manifest, ManifestSHA256: fileSHA(o.Manifest), PredictionsSHA: fileSHA(o.Predictions), BinarySHA256: fileSHA(bin), SourceSHA256: src, SourceTreeSHA256: tree, Versions: Versions()}
	writeJSON(filepath.Join(outDir, "provenance.json"), prov)
	os.WriteFile(filepath.Join(outDir, "manifest-frozen.json"), mb, 0o644)
	if pb, err := os.ReadFile(o.Predictions); err == nil {
		os.WriteFile(filepath.Join(outDir, "predictions-frozen.md"), pb, 0o644)
	}

	sel := map[string]bool{}
	for _, f := range o.Fixtures {
		sel[f] = true
	}
	// Declared run inventory: every cell this run will execute, with its class and
	// expectations, written BEFORE execution so an empty or partial run cannot audit
	// clean. The audit checker compares the cells it finds against this list.
	type invCell struct {
		Cell, Fixture, Policy, Class, PolicyClass, ExpectedDecision, ExpectedRecipient string
		ExpectedDecisions                                                              int // declared cardinality: 2 for the two-appraisal fixtures, else 1
		ClassDerived                                                                   bool
		Capabilities                                                                   []string
	}
	var inv []invCell
	for _, fx := range man.Fixtures {
		if len(sel) > 0 && !sel[fx.ID] {
			continue
		}
		cls, explicit := fx.class()
		for _, p := range man.Policies {
			if fx.Expected[p] == "n/a" {
				continue
			}
			n := 1
			if fx.ID == "F12" || fx.ID == "F13" || fx.ID == "P11" { // nonce-burn and concurrent fixtures export two decisions
				n = 2
			}
			inv = append(inv, invCell{Cell: fx.ID + "_" + p, Fixture: fx.ID, Policy: p, Class: cls, PolicyClass: fx.PolicyClasses[p], ExpectedDecision: fx.Expected[p], ExpectedRecipient: fx.ExpectedRecipientByPolicy[p], ExpectedDecisions: n, ClassDerived: !explicit, Capabilities: fx.Capabilities})
		}
	}
	writeJSON(filepath.Join(outDir, "run-inventory.json"), map[string]any{"run_id": runID, "kind": "matrix", "inventory_schema": 2, "evidence_schema": verifier.EvidenceSchemaVersion, "producer_revision": verifier.ProducerRevision, "manifest": o.Manifest, "manifest_version": man.Version, "declared_before_execution": true, "cells": inv})
	if o.RunPathFile != "" { // exact handoff of THIS run's path to the caller (never "latest directory")
		os.WriteFile(o.RunPathFile, []byte(outDir+"\n"), 0o644)
	}

	rt.Boot()
	defer rt.Shutdown()

	var rows []Row
	var apps []Appraisal
	for _, fx := range man.Fixtures {
		if len(sel) > 0 && !sel[fx.ID] {
			continue
		}
		r, a := runFixture(rt, fx, man.Policies)
		rows = append(rows, r...)
		apps = append(apps, a...)
	}
	var raceSummary string
	if o.Races && man.RaceTrials != nil && len(sel) == 0 {
		raceSummary = runRaces(rt, *man.RaceTrials)
	}
	prov.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	prov.WallSeconds = time.Since(rt.Started).Seconds()
	prov.Commands = rt.Cmds
	writeJSON(filepath.Join(outDir, "provenance.json"), prov)
	writeOutputs(rt, man, rows, apps, raceSummary)
	rt.logf("done: %d cells, %d appraisals, outputs in %s", len(rows), len(apps), outDir)
	return rows, apps, outDir
}

// cell runs one requester decision set with its own isolated session store.
type cell struct {
	rt     *Runtime
	id     string
	dir    string
	req    *verifier.Requester
	trace  *os.File
	events []ctl.Event
	ctl    *ctl.Client
}

func newCell(rt *Runtime, id string, resolver map[string]string) *cell {
	dir := filepath.Join(rt.OutDir, "cells", id)
	os.MkdirAll(dir, 0o755)
	rt.Ctl.SetCell(id, dir)
	tr, _ := os.Create(filepath.Join(dir, "requester-trace.jsonl"))
	cc := ctl.New(ControllerURL, "requester")
	req := verifier.New(rt.Reg, cc, tr)
	req.RootCAs = rt.RootCAs
	req.Resolver = resolver
	return &cell{rt: rt, id: id, dir: dir, req: req, trace: tr, ctl: cc}
}

func (c *cell) finish(decisions []*verifier.Decision) {
	c.trace.Close()
	time.Sleep(150 * time.Millisecond) // let late controller events land
	c.events, _ = c.rt.Ctl.Events(c.id)
	b, _ := json.MarshalIndent(map[string]any{"decisions": decisions, "sessions": c.req.Store.Dump(), "requester_emissions_dropped": c.ctl.Failed}, "", "  ")
	os.WriteFile(filepath.Join(c.dir, "decision.json"), b, 0o644)
}

// truth is the typed ground truth extracted from controller events for one cell.
type truth struct {
	endpoints  []string
	keys       []string // owner labels of enrolled keys that produced proofs (A/B), plus "unenrolled"/"garbage"
	invokers   []string
	materials  []string
	recipients map[string]string // token -> recipient label
	receipts   map[string]int    // token -> count
	rxExporter map[string]string // token -> recipient's own exporter for the receiving connection
	rxDecision map[string]string // token -> decision id echoed by the recipient
	released   map[string]int    // token -> count (job_released)
	exchanges  map[string]int    // nonce -> count of exchange_served
	notes      []string
}

func (c *cell) truth() truth {
	t := truth{recipients: map[string]string{}, receipts: map[string]int{}, released: map[string]int{}, exchanges: map[string]int{}, rxExporter: map[string]string{}, rxDecision: map[string]string{}}
	add := func(list *[]string, s string) {
		if s == "" || s == "<nil>" {
			return
		}
		for _, x := range *list {
			if x == s {
				return
			}
		}
		*list = append(*list, s)
	}
	// First pass: which gates were used for SIGNING (signer_attempt ok with a gate
	// name). A gate connection that only read a PCR (job receipt diagnostic) is not
	// a key use and must not be attributed.
	signingGates := map[string]bool{}
	for _, e := range c.events {
		if e.Kind == "signer_attempt" && e.Data["ok"] == true {
			if g := fmt.Sprint(e.Data["gate"]); g != "" && g != "<nil>" {
				signingGates[g] = true
			}
		}
	}
	for _, e := range c.events {
		d := e.Data
		switch e.Kind {
		case "exchange_served":
			add(&t.endpoints, fmt.Sprint(d["endpoint"]))
			t.exchanges[fmt.Sprint(d["nonce"])]++
		case "gate_conn":
			if d["allowed"] == true {
				if signingGates[fmt.Sprint(d["signer"])] {
					add(&t.invokers, fmt.Sprint(d["peer_label"]))
				}
			} else {
				t.notes = append(t.notes, fmt.Sprintf("gate denied %s to %s", d["signer"], d["peer_label"]))
			}
		case "signer_attempt":
			if d["ok"] != true {
				continue
			}
			kind := fmt.Sprint(d["kind"])
			switch kind {
			case "sfile":
				if owner := c.rt.Reg.KeyOwner(fmt.Sprint(d["key_id"])); owner != "" {
					add(&t.keys, owner)
				}
				add(&t.invokers, fmt.Sprint(d["by"])+"(in-process)")
			case "tpm", "siso":
				// owner of the gate's key material: tpmA / swA / tpmAclone -> A
				g := fmt.Sprint(d["gate"])
				for _, p := range []string{"tpm", "sw"} {
					if strings.HasPrefix(g, p) && len(g) > len(p) {
						add(&t.keys, g[len(p):len(p)+1])
					}
				}
			case "unenrolled", "garbage":
				add(&t.keys, kind)
			case "v4":
				// a2aid-proof-v4: gated custodies are attributed by the gate name
				// (ecA/pqA/devA/devAclone -> A); the volume-held PQ-file key by the key id
				// prefix of the enrolled key that signed; attacker-generated keys explicitly.
				switch sg := fmt.Sprint(d["signer"]); {
				case strings.HasPrefix(sg, "env-gate:"):
					g := strings.TrimSuffix(strings.TrimPrefix(sg, "env-gate:"), ".sock")
					for _, p := range []string{"ec", "pq", "dev"} {
						if strings.HasPrefix(g, p) && len(g) > len(p) {
							add(&t.keys, g[len(p):len(p)+1])
						}
					}
				case sg == "pqfile-seed-in-volume":
					if fmt.Sprint(d["materials"]) == "own" {
						add(&t.keys, fmt.Sprint(d["by"]))
					} else {
						add(&t.keys, "A") // copied volume holds A's seed
					}
					add(&t.invokers, fmt.Sprint(d["by"])+"(in-process)")
				default:
					add(&t.keys, "attacker-generated")
					add(&t.invokers, fmt.Sprint(d["by"])+"(in-process)")
				}
			}
			add(&t.materials, fmt.Sprint(d["materials"]))
		case "job_received":
			tok := fmt.Sprint(d["token"])
			t.recipients[tok] = fmt.Sprint(d["recipient"])
			t.receipts[tok]++
			if x, ok := d["exporter_hex"].(string); ok {
				t.rxExporter[tok] = x
			}
			if x, ok := d["decision_id"].(string); ok {
				t.rxDecision[tok] = x
			}
			add(&t.endpoints, fmt.Sprint(d["recipient"]))
		case "job_released":
			t.released[fmt.Sprint(d["token"])]++
		case "replay_served":
			t.notes = append(t.notes, "B replayed a response for nonce "+short(fmt.Sprint(d["replayed_nonce"])))
		case "relay_forwarded":
			if d["modified"] == true {
				n := fmt.Sprintf("relay edited %s %v -> %v", d["field"], d["old"], d["new"])
				if h, ok := d["inner_quote_sha256_before"]; ok {
					n += fmt.Sprintf("; inner quote sha256 before=%s after=%s", short(fmt.Sprint(h)), short(fmt.Sprint(d["inner_quote_sha256_after"])))
				}
				t.notes = append(t.notes, n)
			} else {
				t.notes = append(t.notes, "relay forwarded A's response unmodified")
			}
		case "relay_leg":
			if inj := fmt.Sprint(d["injected_cb"]); inj != "" && inj != "<nil>" {
				t.notes = append(t.notes, "relay injected its observed channel binding into the forwarded challenge")
			}
		case "ignored_supplied_cb":
			t.notes = append(t.notes, fmt.Sprintf("%s ignored a requester-supplied cb", d["by"]))
		case "binding_unavailable":
			t.notes = append(t.notes, fmt.Sprintf("%s: channel binding unavailable (%s)", d["by"], d["reason"]))
		case "sw_signer_auth_fail":
			t.notes = append(t.notes, fmt.Sprintf("%s rejected token from %s", d["signer"], d["peer_label"]))
		case "lab_hook":
			t.notes = append(t.notes, fmt.Sprint(d["hook"]))
		case "pcr_extended":
			t.notes = append(t.notes, fmt.Sprintf("operator extended PCR16 of %s (%s)", d["label"], d["when"]))
		}
	}
	return t
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

func quoteStr(d *verifier.Decision) (string, string) {
	if d.Quote == nil {
		return "n/a", "n/a"
	}
	if d.Quote.OK() {
		return "ok", "yes"
	}
	return "fail: " + d.Quote.Reason, map[bool]string{true: "yes", false: "no"}[d.Quote.SignatureValid && d.Quote.SignerMatch && d.Quote.NonceMatch && d.Quote.PCRDigestMatch]
}

func envStr(d *verifier.Decision) string {
	if d.SEnv != nil {
		e := d.SEnv
		switch {
		case !e.Decoded:
			return "fail: undecodable"
		case !e.SignatureValid:
			return "fail: signature invalid"
		case !e.MetadataOK:
			return "fail: " + e.Reason
		}
		return "ok"
	}
	e := d.Envelope
	if e == nil {
		return "n/a"
	}
	if !e.Decoded {
		return "fail: undecodable"
	}
	parts := []string{}
	if !e.SignatureValid {
		parts = append(parts, "signature invalid")
	}
	if !e.AttesterKnown {
		parts = append(parts, "attester unknown")
	} else if !e.AttesterMatch {
		parts = append(parts, "attester misbinding")
	}
	if e.SchemaCode != "" {
		parts = append(parts, "schema "+e.SchemaCode)
	}
	if !e.NonceMatch {
		parts = append(parts, "nonce mismatch")
	}
	if e.FreshCode != "" {
		parts = append(parts, "stale "+e.FreshCode)
	}
	if len(parts) == 0 {
		return "ok"
	}
	return "fail: " + strings.Join(parts, "; ")
}

func yn(b bool) string { return map[bool]string{true: "yes", false: "no"}[b] }

// appraisalFrom builds the typed per-decision record.
func appraisalFrom(fx Fixture, policy string, c *cell, t truth, idx int, d *verifier.Decision) Appraisal {
	a := Appraisal{Cell: c.id, Fixture: fx.ID, Policy: policy, Index: idx, ExpectedIdentity: "A (dep-A)", Capabilities: fx.Capabilities, Executed: "n/a (no execution implemented)"}
	if d == nil {
		a.Reason = "no decision"
		return a
	}
	a.EndpointURL = d.Endpoint
	a.EndpointEqual = yn(d.EndpointEqual)
	if d.TLS != nil {
		a.TLSAuthenticated, a.TLSPeerName, a.TLSNameMatch = yn(d.TLS.Authenticated), d.TLS.PeerName, yn(d.TLS.NameMatch)
	} else {
		a.TLSAuthenticated, a.TLSNameMatch = "n/a", "n/a"
	}
	a.CBMatched = "n/a"
	if d.CB != nil {
		a.CBMatched = yn(d.CB.Matched)
	}
	a.CardVerdict = map[bool]string{true: "ok", false: "fail: " + d.Card.Reason}[d.Card.Valid]
	a.SessionVerdict = "n/a"
	if d.Session != nil {
		a.SessionVerdict = map[bool]string{true: "ok", false: "fail: " + d.Session.Reason}[d.Session.ContextMatch && !d.Session.Expired]
	}
	a.NonceVerdict, a.SigVerdict = d.NonceVerdict, d.SigVerdict
	a.QuoteVerdict, a.InnerQuoteValid = quoteStr(d)
	a.EnvelopeVerdict = envStr(d)
	a.Accept, a.FailureStage, a.Code, a.Reason = d.Accept, d.FailureStage, d.Code, d.Reason
	// crypto_accept: every cryptographic check passed, regardless of transport/session stage
	cryptoFail := map[string]bool{"card": true, "signature": true, "quote": true, "trust-anchor": true, "envelope": true, "envelope-signature": true, "envelope-metadata": true, "schema": true, "config": true, "evidence": true, "freshness": true, "nonce": true}
	a.CryptoAccept = d.Accept || !cryptoFail[d.FailureStage]
	if d.FailureStage == "nonce" && d.NonceVerdict == "consumed" {
		a.CryptoAccept = d.SigVerdict == "ok" || (d.Quote != nil && d.Quote.OK())
	}
	a.DispatchAttempted, a.JobToken = d.DispatchAttempted, d.JobToken
	a.AckReceived, a.AckDeployment, a.PCRAtReceipt = d.JobAckReceived, d.JobAckDeployment, d.JobAckPCR
	if d.JobToken != "" {
		a.ObservedRecipient = t.recipients[d.JobToken]
		if a.ObservedRecipient == "" {
			a.ObservedRecipient = "unobserved"
		}
	} else {
		a.ObservedRecipient = "none"
	}
	a.UnauthorizedRecip = d.JobReleased && a.ObservedRecipient != "A"
	a.ConfigChanged = "n/a"
	if d.JobReleased && d.JobAckPCR != "" {
		if dep := c.rt.Reg.Deployments[a.ObservedRecipient]; dep != nil {
			a.ConfigChanged = yn(d.JobAckPCR != dep.PCRReference)
		}
	}
	// endpoint contacted for this appraisal: label whose listener the URL/resolver reached
	a.EndpointContacted = strings.Join(t.endpoints, ">")
	a.KeysUsed, a.Invokers, a.Materials = t.keys, t.invokers, t.materials
	if a.KeysUsed == nil {
		a.KeysUsed = []string{}
	}
	pol, _ := wire.ParsePolicy(policy)
	honest := fx.Endpoint == "A"
	a.LegitimateRejection = honest && !d.Accept
	a.SignerOK = "n/a"
	if d.Accept && pol.HasProof() {
		hasA := false
		for _, k := range t.keys {
			if k == "A" {
				hasA = true
			}
		}
		a.SignerOK = map[bool]string{true: "correct", false: "false-attribution"}[hasA]
		for _, m := range t.materials {
			if strings.HasPrefix(m, "copied-volume") {
				a.CustodyBroken = true
			}
		}
		for _, inv := range t.invokers {
			if strings.HasPrefix(inv, "B") && hasA {
				a.CustodyBroken = true
			}
		}
	}
	// release evidence
	a.DecisionID, a.JobSent, a.JobConnReused, a.PinnedConnID, a.DispatchConnID = d.DecisionID, d.JobSent, d.JobConnReused, d.PinnedConnID, d.DispatchConnID
	a.DispatchOutcome = "none"
	for _, e := range d.Events {
		switch e.Kind {
		case "ack":
			a.DispatchOutcome = "acked"
		case "refused_reconnect", "refused_dispatch", "unknown_outcome", "dispatch_error":
			a.DispatchOutcome = map[string]string{"refused_reconnect": "refused_reconnect", "refused_dispatch": "refused_dispatch", "unknown_outcome": "unknown_outcome", "dispatch_error": "error"}[e.Kind]
		}
	}
	a.ReceiptExporterMatch, a.ReceiptDecisionID = "n/a", "n/a"
	if d.JobToken != "" && t.receipts[d.JobToken] > 0 {
		if rx := t.rxExporter[d.JobToken]; rx != "" && d.PinnedConnID > 0 && d.PinnedConnID <= len(d.Conns) {
			a.ReceiptExporterMatch = yn(d.Conns[d.PinnedConnID-1].ExporterHex == rx)
		}
		if rd := t.rxDecision[d.JobToken]; rd != "" {
			a.ReceiptDecisionID = yn(rd == d.DecisionID)
		}
	}
	// telemetry completeness
	var missing []string
	if d.Nonce != "" && !strings.HasPrefix(d.FailureStage, "connect") && d.FailureStage != "policy" && t.exchanges[d.Nonce] == 0 {
		missing = append(missing, "exchange_served for nonce")
	}
	if d.JobReleased && t.receipts[d.JobToken] == 0 {
		missing = append(missing, "job_received for token")
	}
	if c.ctl.Failed > 0 {
		missing = append(missing, fmt.Sprintf("%d requester emissions dropped", c.ctl.Failed))
	}
	if len(missing) == 0 {
		a.Telemetry = "complete"
	} else {
		a.Telemetry = "missing: " + strings.Join(missing, "; ")
	}
	return a
}

func rowFrom(fx Fixture, policy string, c *cell, t truth, apps []Appraisal, observed string) Row {
	r := Row{Cell: c.id, Fixture: fx.ID, FixtureTitle: fx.Title, Policy: policy, Capabilities: fx.Capabilities, Appraisals: len(apps),
		ExpectedResult: fx.Expected[policy], ObservedResult: observed, Notes: t.notes}
	r.Class, _ = fx.class()
	r.DecisionMatch = r.ExpectedResult == r.ObservedResult
	r.Match = r.DecisionMatch
	r.EndpointContacted = strings.Join(t.endpoints, ">")
	recips := []string{}
	for tok, who := range t.recipients {
		recips = append(recips, who)
		if t.receipts[tok] > 1 {
			r.DuplicateReceipt = true
		}
	}
	sort.Strings(recips)
	r.JobRecipients = strings.Join(recips, ",")
	if r.JobRecipients == "" {
		r.JobRecipients = "none"
	}
	if er, ok := fx.ExpectedRecipientByPolicy[policy]; ok {
		r.ExpectedRecipient, r.RecipientChecked = er, true
		r.RecipientMatch = r.JobRecipients == er
		r.Match = r.DecisionMatch && r.RecipientMatch
	}
	for _, n := range t.released {
		r.Releases += n
		if n > 1 {
			r.DuplicateDispatch = true
		}
	}
	for _, n := range t.receipts {
		r.Receipts += n
	}
	if len(apps) > 0 {
		a := apps[0]
		r.Decision = map[bool]string{true: "accept", false: "reject"}[a.Accept]
		r.FailureStage, r.Code, r.Reason = a.FailureStage, a.Code, a.Reason
		if r.EndpointContacted == "" {
			r.EndpointContacted = "(none contacted)"
		}
	}
	return r
}

func endpointURL(label string, pol wire.Policy) string {
	switch {
	case label == "B" && pol.TLS:
		return BTLSURL
	case label == "B":
		return BURL
	case pol.TLS:
		return ATLSURL
	}
	return AURL
}

func (c *cell) runStandard(policy, endpointLabel string, hooks map[string]string) *verifier.Decision {
	pol, _ := wire.ParsePolicy(policy)
	d, err := c.req.Run(context.Background(), policy, endpointURL(endpointLabel, pol), "A", hooks)
	if err != nil {
		c.rt.logf("cell %s: %v", c.id, err)
	}
	return d
}

func decisionStr(d *verifier.Decision) string {
	if d == nil {
		return "error"
	}
	return map[bool]string{true: "accept", false: "reject"}[d.Accept]
}

func honest(cardPath string) map[string]any {
	return map[string]any{"mode": "honest", "card_path": cardPath}
}

// relayMode builds B's relay configuration towards the real A.
func relayMode(mode, cardPath string, pol wire.Policy, extra map[string]any) map[string]any {
	m := map[string]any{"mode": mode, "card_path": cardPath, "relay_to": endpointURL("A", pol), "relay_resolve": DefaultResolver}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// runFixture executes all applicable policies for one fixture.
func runFixture(rt *Runtime, fx Fixture, policies []string) ([]Row, []Appraisal) {
	var rows []Row
	var apps []Appraisal
	copiedCard := filepath.Join(rt.AbsRun, "B", "copied-volume", "app", "card.json")
	copiedApp := filepath.Dir(copiedCard)
	bOwnCard := filepath.Join(rt.AbsRun, "B", "app", "card.json")
	aSigner := filepath.Join(rt.AbsRun, "A", "signer")
	aTLS := filepath.Join(rt.AbsRun, "A", "tls")
	selfSignedAsA := filepath.Join(rt.AbsRun, "B", "tls-selfsigned-as-A")
	rt.logf("=== %s %s", fx.ID, fx.Title)

	// Fixture-level setup (shared across policies).
	switch fx.ID {
	case "F2":
		rt.Publish("A", "Atlas Prime", "1.1.0", []string{AURL, ATLSURL}, AAdmin)
	case "F3":
		rt.Publish("B", "Atlas Prime", "1.1.0", []string{BURL, BTLSURL}, BAdmin)
	case "F4":
		writeJSON(filepath.Join(rt.OutDir, "copy-manifest-"+fx.ID+".json"), rt.CopyVolume(fx.ID, []string{"card.json"}))
	case "F5", "F6", "F7", "F8", "F11", "F12", "F13", "F14", "F15", "F16", "F17", "F20", "V2", "V3", "V4":
		writeJSON(filepath.Join(rt.OutDir, "copy-manifest-"+fx.ID+".json"), rt.CopyVolume(fx.ID, []string{"card.json", "config.json", "sfile.key"}))
		if fx.ID == "F7" || fx.ID == "F20" {
			rt.SetACL(map[string][]string{"tpmA": {"A", "B", "operator"}, "tpmB": {"B", "operator"}, "swA": {"A", "B"}, "swB": {"B"}})
		}
	// ---- PQ identity fixtures (a2aid-proof-v4; fixtures/manifest-pq.json) ----
	case "P2", "P3", "P4", "P5", "P7", "P8", "P9", "P10", "X3":
		writeJSON(filepath.Join(rt.OutDir, "copy-manifest-"+fx.ID+".json"), rt.CopyVolume(fx.ID, []string{"card.json"}))
	case "P6", "P12", "X1", "X4":
		files := []string{"card.json", "config.json", "sfile.key", "pqfile.seed"}
		if fx.ID == "P12" { // classical-compromise surrogate: the volume copy excludes the PQ-file seed (no PQ key of A)
			files = []string{"card.json", "config.json", "sfile.key"}
		}
		writeJSON(filepath.Join(rt.OutDir, "copy-manifest-"+fx.ID+".json"), rt.CopyVolume(fx.ID, files))
		acl := map[string][]string{}
		for k, v := range rt.ACLDefault {
			acl[k] = v
		}
		switch fx.ID {
		case "P12":
			acl["ecA"] = []string{"A", "B"}
		case "X1":
			acl["pqA"], acl["devA"] = []string{"A", "B"}, []string{"A", "B"}
		case "X4":
			k := rt.Reg.Deployments["A"].V4Keys[wire.PolicyPQFile]
			rt.pqFileKeyBackup = &k
			k.KID, k.Version = "A-pqfile-k2", 2 // rotated pin; the public key stays (the kid/version check must fire first)
			rt.Reg.Deployments["A"].V4Keys[wire.PolicyPQFile] = k
			// Declared per-fixture trust-anchor override, recorded for the audit.
			ov := map[string]map[string]map[string]registry.V4Key{}
			if b, err := os.ReadFile(filepath.Join(rt.OutDir, "registry-overrides.json")); err == nil {
				json.Unmarshal(b, &ov)
			}
			if ov[fx.ID] == nil {
				ov[fx.ID] = map[string]map[string]registry.V4Key{}
			}
			ov[fx.ID]["A"] = map[string]registry.V4Key{wire.PolicyPQFile: k}
			writeJSON(filepath.Join(rt.OutDir, "registry-overrides.json"), ov)
		}
		rt.SetACL(acl)
	case "X2":
		writeJSON(filepath.Join(rt.OutDir, "copy-manifest-"+fx.ID+"-volume.json"), rt.CopyVolume(fx.ID, []string{"card.json", "config.json", "sfile.key", "pqfile.seed"}))
		writeJSON(filepath.Join(rt.OutDir, "copy-manifest-"+fx.ID+"-fwtpm-state.json"), rt.CloneFWTPM(fx.ID, pqdev.DefaultBin("."), 2341))
	case "F19", "F21":
		writeJSON(filepath.Join(rt.OutDir, "copy-manifest-"+fx.ID+"-volume.json"), rt.CopyVolume(fx.ID, []string{"card.json", "config.json", "sfile.key"}))
		writeJSON(filepath.Join(rt.OutDir, "copy-manifest-"+fx.ID+"-tpm-state.json"), rt.CloneTPM(fx.ID))
		if fx.ID == "F21" {
			// PCRs are volatile: the clone boots with PCR 16 = 0. The attacker extends
			// it with the PUBLIC configuration string (harness does this on B's behalf
			// through the clone's gate socket) so the quote digest matches the reference.
			oc, err := tpmsig.Open(filepath.Join(rt.AbsRun, "gate", "tpmAclone.sock"))
			if err != nil {
				panic(err)
			}
			if err := oc.ExtendPCR([]byte("deployment-A-config-v1")); err != nil {
				panic(err)
			}
			v, _ := oc.ReadPCR()
			oc.Close()
			rt.Ctl.Emit("pcr_extended", map[string]any{"label": "A-clone", "when": "before the cell, by the attacker with the public config string", "value": fmt.Sprintf("%x", v)})
		}
	case "F9":
		c := rt.OperatorTPM("A")
		if err := c.ExtendPCR([]byte("unexpected-config-drift")); err != nil {
			panic(err)
		}
		c.Close()
	}

	for _, policy := range policies {
		exp := fx.Expected[policy]
		if exp == "n/a" {
			rows = append(rows, Row{Cell: fx.ID + "_" + policy, Fixture: fx.ID, FixtureTitle: fx.Title, Policy: policy, Capabilities: fx.Capabilities, ExpectedResult: "n/a", ObservedResult: "n/a", Match: true, Decision: "n/a", JobRecipients: "n/a"})
			continue
		}
		pol, err := wire.ParsePolicy(policy)
		if err != nil {
			panic(err)
		}
		resolver := DefaultResolver
		if fx.Endpoint == "A-hijacked" {
			resolver = HijackResolver
		}
		c := newCell(rt, fx.ID+"_"+policy, resolver)
		var ds []*verifier.Decision
		var observed string
		switch fx.ID {
		case "F1", "F2", "F9":
			rt.SetMode(BAdmin, honest(bOwnCard))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "F10":
			rt.SetMode(BAdmin, honest(bOwnCard))
			ds = []*verifier.Decision{c.runStandard(policy, "A", map[string]string{"ptv_malform": "both"})}
		case "F18":
			rt.SetMode(BAdmin, honest(bOwnCard))
			c.req.Hook = func(stage string, d *verifier.Decision) {
				if !d.Accept {
					return
				}
				oc := rt.OperatorTPM("A")
				if err := oc.ExtendPCR([]byte("post-appraisal-config-change")); err != nil {
					panic(err)
				}
				oc.Close()
				rt.Ctl.Emit("pcr_extended", map[string]any{"label": "A", "when": "after appraisal, before job release"})
			}
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
			restorePCR(rt)
		case "F3":
			rt.SetMode(BAdmin, honest(bOwnCard))
			ds = []*verifier.Decision{c.runStandard(policy, "B", nil)}
		case "F4":
			var replay map[string]any
			if pol.HasProof() {
				prep := verifier.New(rt.Reg, ctl.New(ControllerURL, "prep-requester"), nil)
				prep.RootCAs, prep.Resolver = rt.RootCAs, DefaultResolver
				pd := &verifier.Decision{Policy: policy, Expected: "A"}
				client, err := prep.Connect(context.Background(), endpointURL("A", pol), "A", pd)
				if err != nil {
					panic(err)
				}
				n, _ := prep.Issue("A", policy)
				replay, err = prep.SendChallenge(context.Background(), client, policy, n, "A", nil)
				client.Destroy()
				if err != nil {
					panic(err)
				}
				writeJSON(filepath.Join(c.dir, "captured-old-response.json"), replay)
			}
			rt.SetMode(BAdmin, map[string]any{"mode": "replay", "card_path": copiedCard, "replay_evidence": replay})
			ds = []*verifier.Decision{c.runStandard(policy, "B", nil)}
		case "F5":
			rt.SetMode(BAdmin, map[string]any{"mode": "copied-volume", "card_path": copiedCard, "foreign_app_dir": copiedApp})
			ds = []*verifier.Decision{c.runStandard(policy, "B", nil)}
		case "F7":
			rt.SetMode(BAdmin, map[string]any{"mode": "socket-access", "card_path": copiedCard, "foreign_app_dir": copiedApp, "foreign_signer_dir": aSigner})
			ds = []*verifier.Decision{c.runStandard(policy, "B", nil)}
		case "F6":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, nil))
			ds = []*verifier.Decision{c.runStandard(policy, "B", nil)}
		case "F8":
			rt.SetMode(BAdmin, relayMode("tamper", copiedCard, pol, map[string]any{"tamper_delta_sec": 60}))
			ds = []*verifier.Decision{c.runStandard(policy, "B", nil)}
		case "F11":
			rt.SetMode(BAdmin, map[string]any{"mode": "unknown-key", "card_path": copiedCard})
			ds = []*verifier.Decision{c.runStandard(policy, "B", nil)}
		case "F12":
			rt.SetMode(BAdmin, map[string]any{"mode": "invalid", "card_path": copiedCard})
			ds, observed = c.runNonceBurn(policy)
		case "F13":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, nil))
			ds, observed = c.runConcurrent(policy)
		case "F14":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, nil))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)} // resolver sends A's name to B
		case "F15":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, map[string]any{"tls_identity_dir": aTLS}))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "F16":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, map[string]any{"tls_identity_dir": aTLS, "inject_cb": true}))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "F17":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, map[string]any{"tls_identity_dir": selfSignedAsA}))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "F19", "F21":
			rt.SetMode(BAdmin, map[string]any{"mode": "socket-access", "card_path": copiedCard, "foreign_app_dir": copiedApp, "foreign_signer_dir": aSigner, "foreign_ak_auth_only": true})
			ds = []*verifier.Decision{c.runStandard(policy, "B", nil)}
		case "F20":
			rt.SetMode(BAdmin, map[string]any{"mode": "socket-access", "card_path": copiedCard, "foreign_app_dir": copiedApp, "foreign_signer_dir": aSigner, "tls_identity_dir": aTLS})
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "V1":
			rt.SetMode(BAdmin, honest(bOwnCard))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "V2":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, map[string]any{"tls_identity_dir": aTLS}))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "V3":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, map[string]any{"tls_identity_dir": aTLS, "chosen_nonce": true, "strip_binding": true}))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "V4":
			fwd := map[string]string{"S-env+cb": wire.PolicySEnv, "T+cb": wire.PolicyT, "S-env+tls": wire.PolicySEnv, "T+tls": wire.PolicyT, "C+tls": wire.PolicyC, "C+url": wire.PolicyC}[policy]
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, map[string]any{"tls_identity_dir": aTLS, "chosen_nonce": true, "strip_binding": true, "forward_policy": fwd}))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		// ---- PQ identity fixtures ----
		case "P1":
			rt.SetMode(BAdmin, honest(bOwnCard))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "P2":
			var replay map[string]any
			if pol.HasProof() {
				prep := verifier.New(rt.Reg, ctl.New(ControllerURL, "prep-requester"), nil)
				prep.RootCAs, prep.Resolver = rt.RootCAs, DefaultResolver
				pd := &verifier.Decision{Policy: policy, Expected: "A"}
				client, err := prep.Connect(context.Background(), endpointURL("A", pol), "A", pd)
				if err != nil {
					panic(err)
				}
				n, _ := prep.Issue("A", policy)
				replay, err = prep.SendChallenge(context.Background(), client, policy, n, "A", nil)
				client.Destroy()
				if err != nil {
					panic(err)
				}
				writeJSON(filepath.Join(c.dir, "captured-old-response.json"), replay)
			}
			rt.SetMode(BAdmin, map[string]any{"mode": "replay", "card_path": copiedCard, "replay_evidence": replay})
			ds = []*verifier.Decision{c.runStandard(policy, "B", nil)}
		case "P3":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, map[string]any{"tls_identity_dir": aTLS, "tamper_context": "action"}))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "P4":
			rt.SetMode(BAdmin, map[string]any{"mode": "impostor-own-keys", "card_path": copiedCard, "tls_identity_dir": aTLS, "claim_kid_prefix": "A"})
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "P5":
			rt.SetMode(BAdmin, map[string]any{"mode": "alg-confusion", "card_path": copiedCard, "tls_identity_dir": aTLS, "claim_kid_prefix": "A"})
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "P6", "X4":
			rt.SetMode(BAdmin, map[string]any{"mode": "copied-volume", "card_path": copiedCard, "foreign_app_dir": copiedApp, "tls_identity_dir": aTLS, "claim_kid_prefix": "A"})
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "P7":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, nil))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "P8":
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, map[string]any{"tls_identity_dir": aTLS}))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "P9":
			extra := map[string]any{"tls_identity_dir": aTLS, "chosen_nonce": true, "strip_binding": true, "inject_cb": true}
			if pol.CB && pol.Base != wire.PolicyC {
				extra["forward_policy"] = pol.Base + "+tls"
			}
			rt.SetMode(BAdmin, relayMode("relay", copiedCard, pol, extra))
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "P10":
			// B stands ready as A (A's TLS credentials, copied card, honest mode). After
			// the appraisal the proof connection is closed and A's TLS name is repointed
			// to B; the sealed transport must refuse the reconnect before any task byte.
			rt.SetMode(BAdmin, map[string]any{"mode": "honest", "card_path": copiedCard, "tls_identity_dir": aTLS})
			res := map[string]string{}
			for k, v := range DefaultResolver {
				res[k] = v
			}
			c.req.Resolver = res
			c.req.Hook = func(stage string, d *verifier.Decision) {
				if stage != "after-appraise" || !d.Accept {
					return
				}
				d.LabCloseConns()
				res["a.a2aid.test:9443"] = "127.0.0.1:9444"
				rt.Ctl.Emit("lab_hook", map[string]any{"fixture": "P10", "stage": stage, "action": "closed proof connections; a.a2aid.test:9443 now resolves to B"})
			}
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "P11":
			rt.SetMode(BAdmin, honest(bOwnCard))
			ds, observed = c.runConcurrent(policy)
		case "P12", "X1", "X2":
			rt.SetMode(BAdmin, map[string]any{"mode": "socket-access", "card_path": copiedCard, "foreign_app_dir": copiedApp, "foreign_signer_dir": aSigner, "tls_identity_dir": aTLS, "claim_kid_prefix": "A"})
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		case "X3":
			rt.SetMode(BAdmin, map[string]any{"mode": "fresh-pq-key", "card_path": copiedCard, "tls_identity_dir": aTLS, "claim_kid_prefix": "A"})
			ds = []*verifier.Decision{c.runStandard(policy, "A", nil)}
		default:
			panic("unknown fixture " + fx.ID)
		}
		if observed == "" {
			observed = decisionStr(ds[0])
		}
		c.finish(ds)
		t := c.truth()
		var cellApps []Appraisal
		for i, d := range ds {
			cellApps = append(cellApps, appraisalFrom(fx, policy, c, t, i+1, d))
		}
		row := rowFrom(fx, policy, c, t, cellApps, observed)
		for i, a := range cellApps {
			if i > 0 {
				row.Notes = append(row.Notes, fmt.Sprintf("appraisal %d: %s stage=%s code=%s reason=%s", i+1, map[bool]string{true: "accept", false: "reject"}[a.Accept], a.FailureStage, a.Code, a.Reason))
			}
			if a.Telemetry != "complete" {
				row.Notes = append(row.Notes, "telemetry "+a.Telemetry)
			}
			if a.ConfigChanged == "yes" {
				row.Notes = append(row.Notes, "configuration changed between appraisal and delivery (PCR at receipt != reference)")
			}
		}
		rt.logf("%-14s expected=%-14s observed=%-14s job->%s keys=%v %s", c.id, row.ExpectedResult, row.ObservedResult, row.JobRecipients, t.keys, row.Reason)
		rows = append(rows, row)
		apps = append(apps, cellApps...)
	}

	// Fixture-level teardown.
	switch fx.ID {
	case "F3":
		rt.Publish("B", "Boreas", "1.0.0", []string{BURL, BTLSURL}, BAdmin)
	case "F7", "F20":
		rt.SetACL(rt.ACLDefault)
	case "F9":
		restorePCR(rt)
	case "F19", "F21":
		rt.StopClone()
	case "P12", "X1":
		rt.SetACL(rt.ACLDefault)
	case "X2":
		rt.StopFWClone()
	case "X4":
		if rt.pqFileKeyBackup != nil {
			rt.Reg.Deployments["A"].V4Keys[wire.PolicyPQFile] = *rt.pqFileKeyBackup
			rt.pqFileKeyBackup = nil
		}
	}
	rt.SetMode(BAdmin, honest(bOwnCard))
	return rows, apps
}

func restorePCR(rt *Runtime) {
	c := rt.OperatorTPM("A")
	if err := c.ResetPCR(); err != nil {
		panic(err)
	}
	if err := c.ExtendPCR([]byte("deployment-A-config-v1")); err != nil {
		panic(err)
	}
	v, _ := c.ReadPCR()
	c.Close()
	if fmt.Sprintf("%x", v) != rt.Reg.Deployments["A"].PCRReference {
		panic("PCR restore failed")
	}
	rt.logf("PCR16 of A restored to reference")
}

// runNonceBurn: B answers the nonce invalidly first; the same nonce is then sent to
// A. Under +url/+tls the first leg fails at connect (no nonce issued yet), which is
// recorded as a rejection without a burned nonce.
func (c *cell) runNonceBurn(policy string) ([]*verifier.Decision, string) {
	ctx := context.Background()
	pol, _ := wire.ParsePolicy(policy)
	// Both decisions use the requester's own lifecycle helpers (Challenge /
	// AppraiseRecord / Release) so that their records carry the same schema, typed
	// context and events as a Run decision.
	d1 := &verifier.Decision{Policy: policy, Expected: "A"}
	cb, err := c.req.Connect(ctx, endpointURL("B", pol), "A", d1)
	var nonce string
	if err == nil {
		defer cb.Destroy()
		nonce, _ = c.req.Issue("A", policy)
		if raw1, err := c.req.Challenge(ctx, cb, d1, nonce, nil); err == nil {
			c.req.AppraiseRecord(d1, nonce, raw1)
			c.req.Release(ctx, cb, nonce, d1)
		}
	}
	d2 := &verifier.Decision{Policy: policy, Expected: "A"}
	ca, err := c.req.Connect(ctx, endpointURL("A", pol), "A", d2)
	if err != nil {
		panic(err)
	}
	defer ca.Destroy()
	if nonce == "" {
		nonce, _ = c.req.Issue("A", policy) // first leg never got a nonce; A gets a fresh one
	}
	if raw2, err := c.req.Challenge(ctx, ca, d2, nonce, nil); err == nil { // deliberate reuse of the burned nonce when one exists
		c.req.AppraiseRecord(d2, nonce, raw2)
		c.req.Release(ctx, ca, nonce, d2)
	}
	return []*verifier.Decision{d1, d2}, decisionStr(d1) + "," + decisionStr(d2)
}

// runConcurrent: one nonce, delivered to A directly and to B (relay) at the same
// time; both VALID responses exist before the two appraisals start concurrently.
func (c *cell) runConcurrent(policy string) ([]*verifier.Decision, string) {
	ctx := context.Background()
	pol, _ := wire.ParsePolicy(policy)
	dA := &verifier.Decision{Policy: policy, Expected: "A"}
	dB := &verifier.Decision{Policy: policy, Expected: "A"}
	ca, err := c.req.Connect(ctx, endpointURL("A", pol), "A", dA)
	if err != nil {
		panic(err)
	}
	defer ca.Destroy()
	cb, errB := c.req.Connect(ctx, endpointURL("B", pol), "A", dB)
	if errB == nil {
		defer cb.Destroy()
	}
	if !pol.HasProof() {
		// Card-only policies issue no nonce (as in Run): each leg is appraised on its
		// own connection and released under its own synthetic session.
		c.req.Appraise(policy, "", "A", map[string]any{}, dA)
		c.req.AppraiseRecordNoNonce(dA)
		c.req.Release(ctx, ca, "", dA)
		if errB == nil {
			c.req.Appraise(policy, "", "A", map[string]any{}, dB)
			c.req.AppraiseRecordNoNonce(dB)
			c.req.Release(ctx, cb, "", dB)
		}
		n := 0
		for _, d := range []*verifier.Decision{dA, dB} {
			if d.JobReleased {
				n++
			}
		}
		obs := "one"
		if n != 1 {
			obs = fmt.Sprintf("%d releases", n)
		}
		return []*verifier.Decision{dA, dB}, obs
	}
	nonce, _ := c.req.Issue("A", policy)
	var rawA, rawB map[string]any
	var errA, errBx error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawA, errA = c.req.Challenge(ctx, ca, dA, nonce, nil)
	}()
	if errB == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rawB, errBx = c.req.Challenge(ctx, cb, dB, nonce, nil)
		}()
	}
	wg.Wait()
	// Both VALID responses exist; the two appraisals (and releases) now race for the
	// one nonce. Each decision keeps its own lifecycle record.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if errA == nil {
			c.req.AppraiseRecord(dA, nonce, rawA)
			c.req.Release(ctx, ca, nonce, dA)
		}
	}()
	if errB == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if errBx == nil {
				c.req.AppraiseRecord(dB, nonce, rawB)
				c.req.Release(ctx, cb, nonce, dB)
			}
		}()
	}
	wg.Wait()
	n := 0
	for _, d := range []*verifier.Decision{dA, dB} {
		if d.JobReleased {
			n++
		}
	}
	obs := "one"
	if n != 1 {
		obs = fmt.Sprintf("%d releases", n)
	}
	return []*verifier.Decision{dA, dB}, obs
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, b, 0o644)
}

func writeOutputs(rt *Runtime, man Manifest, rows []Row, apps []Appraisal, raceSummary string) {
	f, _ := os.Create(filepath.Join(rt.OutDir, "matrix.jsonl"))
	for _, r := range rows {
		b, _ := json.Marshal(r)
		f.Write(append(b, '\n'))
	}
	f.Close()
	cf, _ := os.Create(filepath.Join(rt.OutDir, "matrix.csv"))
	w := csv.NewWriter(cf)
	w.Write([]string{"cell", "fixture", "policy", "attacker_capabilities", "appraisals", "endpoint_contacted", "decision", "job_recipients", "releases", "receipts", "duplicate_dispatch", "duplicate_receipt", "failure_stage", "code", "reason", "expected_result", "observed_result", "match", "notes", "class", "expected_recipient", "decision_match", "recipient_match", "recipient_checked"})
	for _, r := range rows {
		w.Write([]string{r.Cell, r.Fixture, r.Policy, strings.Join(r.Capabilities, ";"), fmt.Sprint(r.Appraisals), r.EndpointContacted, r.Decision, r.JobRecipients, fmt.Sprint(r.Releases), fmt.Sprint(r.Receipts), fmt.Sprint(r.DuplicateDispatch), fmt.Sprint(r.DuplicateReceipt), r.FailureStage, r.Code, r.Reason, r.ExpectedResult, r.ObservedResult, fmt.Sprint(r.Match), strings.Join(r.Notes, " / "), r.Class, r.ExpectedRecipient, fmt.Sprint(r.DecisionMatch), fmt.Sprint(r.RecipientMatch), fmt.Sprint(r.RecipientChecked)})
	}
	w.Flush()
	cf.Close()
	af, _ := os.Create(filepath.Join(rt.OutDir, "appraisals.jsonl"))
	for _, a := range apps {
		b, _ := json.Marshal(a)
		af.Write(append(b, '\n'))
	}
	af.Close()
	acf, _ := os.Create(filepath.Join(rt.OutDir, "appraisals.csv"))
	aw := csv.NewWriter(acf)
	aw.Write([]string{"cell", "fixture", "policy", "appraisal_index", "expected_identity", "attacker_capabilities", "endpoint_url", "endpoint_contacted", "endpoint_equal", "tls_authenticated", "tls_peer_name", "tls_name_match", "cb_matched", "card_verdict", "session_verdict", "nonce_verdict", "sig_verdict", "quote_verdict", "envelope_verdict", "inner_quote_valid", "crypto_accept", "accept", "failure_stage", "code", "reason", "dispatch_attempted", "job_token", "observed_recipient", "ack_received", "ack_claimed_deployment", "executed", "pcr_at_receipt_hex", "config_changed_before_delivery", "unauthorized_recipient_access", "legitimate_rejection", "keys_used", "invokers", "materials", "signer_attribution", "custody_broken", "telemetry", "decision_id", "job_sent", "job_reused_proof_connection", "pinned_conn_id", "dispatch_conn_id", "dispatch_outcome", "receipt_exporter_match", "receipt_decision_id_match"})
	for _, a := range apps {
		aw.Write([]string{a.Cell, a.Fixture, a.Policy, fmt.Sprint(a.Index), a.ExpectedIdentity, strings.Join(a.Capabilities, ";"), a.EndpointURL, a.EndpointContacted, a.EndpointEqual, a.TLSAuthenticated, a.TLSPeerName, a.TLSNameMatch, a.CBMatched, a.CardVerdict, a.SessionVerdict, a.NonceVerdict, a.SigVerdict, a.QuoteVerdict, a.EnvelopeVerdict, a.InnerQuoteValid, fmt.Sprint(a.CryptoAccept), fmt.Sprint(a.Accept), a.FailureStage, a.Code, a.Reason, fmt.Sprint(a.DispatchAttempted), a.JobToken, a.ObservedRecipient, fmt.Sprint(a.AckReceived), a.AckDeployment, a.Executed, a.PCRAtReceipt, a.ConfigChanged, fmt.Sprint(a.UnauthorizedRecip), fmt.Sprint(a.LegitimateRejection), strings.Join(a.KeysUsed, ";"), strings.Join(a.Invokers, ";"), strings.Join(a.Materials, ";"), a.SignerOK, fmt.Sprint(a.CustodyBroken), a.Telemetry, a.DecisionID, fmt.Sprint(a.JobSent), fmt.Sprint(a.JobConnReused), fmt.Sprint(a.PinnedConnID), fmt.Sprint(a.DispatchConnID), a.DispatchOutcome, a.ReceiptExporterMatch, a.ReceiptDecisionID})
	}
	aw.Flush()
	acf.Close()
	os.WriteFile(filepath.Join(rt.OutDir, "versions.txt"), []byte(Versions()), 0o644)
	if rb, err := os.ReadFile(filepath.Join(rt.AbsRun, "registry.json")); err == nil {
		os.WriteFile(filepath.Join(rt.OutDir, "enrollment-registry.json"), rb, 0o644) // public keys and reference values only
	}
	os.WriteFile(filepath.Join(rt.OutDir, "commands-executed.txt"), []byte(strings.Join(rt.Cmds, "\n")+"\n"), 0o644)
	os.WriteFile(filepath.Join(rt.OutDir, "summary.md"), []byte(summary(man, rows, apps, rt, raceSummary)), 0o644)
}
