package matrix

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"a2aid/internal/ctl"
	"a2aid/internal/ptv"
	"a2aid/internal/wire"
)

// TracesMain extracts sanitized paired traces from a results directory.
func TracesMain(args []string) {
	fs := flag.NewFlagSet("traces", flag.ExitOnError)
	res := fs.String("results", "", "results run directory (e.g. results/full/2026...)")
	fs.Parse(args)
	if *res == "" {
		fs.Usage()
		os.Exit(2)
	}
	out := filepath.Join(*res, "traces")
	os.MkdirAll(out, 0o755)
	write := func(name, body string) {
		os.WriteFile(filepath.Join(out, name), []byte(body), 0o644)
		fmt.Println("wrote", filepath.Join(out, name))
	}
	write("copy-pair.md", copyPair(*res))
	write("relay-pair.md", relayPair(*res))
	write("cose-tamper-pair.md", coseTamperPair(*res))
}

func loadEvents(res, cell string) []ctl.Event {
	f, err := os.Open(filepath.Join(res, "cells", cell, "controller-events.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var evs []ctl.Event
	dec := json.NewDecoder(f)
	for dec.More() {
		var e ctl.Event
		if dec.Decode(&e) == nil {
			evs = append(evs, e)
		}
	}
	return evs
}

func loadDecision(res, cell string) map[string]any {
	b, err := os.ReadFile(filepath.Join(res, "cells", cell, "decision.json"))
	if err != nil {
		return nil
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func loadTrace(res, cell string) []map[string]any {
	f, err := os.Open(filepath.Join(res, "cells", cell, "requester-trace.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []map[string]any
	dec := json.NewDecoder(f)
	for dec.More() {
		var m map[string]any
		if dec.Decode(&m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func pretty(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	s := string(b)
	// keep long base64 fields readable
	if len(s) > 6000 {
		s = s[:6000] + "\n… (truncated)"
	}
	return "```json\n" + s + "\n```\n"
}

func eventTimeline(evs []ctl.Event, skip ...string) string {
	var sb strings.Builder
	sb.WriteString("| time | source | event | key fields |\n|---|---|---|---|\n")
	for _, e := range evs {
		skipIt := false
		for _, k := range skip {
			if e.Kind == k {
				skipIt = true
			}
		}
		if skipIt {
			continue
		}
		d := map[string]any{}
		for k, v := range e.Data {
			if k == "payload" || k == "original" || k == "acl" {
				continue
			}
			if s, ok := v.(string); ok && len(s) > 24 {
				v = s[:24] + "…"
			}
			d[k] = v
		}
		b, _ := json.Marshal(d)
		fmt.Fprintf(&sb, "| %s | %s | %s | `%s` |\n", e.TS[11:23], e.Source, e.Kind, strings.ReplaceAll(string(b), "|", "/"))
	}
	return sb.String()
}

func firstDecision(res, cell string) map[string]any {
	d := loadDecision(res, cell)
	if d == nil {
		return nil
	}
	if ds, ok := d["decisions"].([]any); ok && len(ds) > 0 {
		m, _ := ds[0].(map[string]any)
		return m
	}
	return nil
}

func decisionSummary(d map[string]any) string {
	if d == nil {
		return "(missing)\n"
	}
	keys := []string{"policy", "endpoint_url", "card", "url_binding", "nonce_verdict", "sig_verdict", "quote", "envelope", "claimed_deployment", "accept", "code", "failure_stage", "reason", "job_released", "job_ack_claimed_deployment"}
	m := map[string]any{}
	for _, k := range keys {
		if v, ok := d[k]; ok {
			m[k] = v
		}
	}
	return pretty(m)
}

func copyPair(res string) string {
	var sb strings.Builder
	sb.WriteString("# Paired trace: application-volume copy (F5)\n\nB holds a byte copy of A's `app/` volume (signed card, config, exportable S-file key) and its own TPM. Gate ACL denies B on A's signers. Same requester routing; policies S-file and T compared, S-iso as the equivalent-access-control software control.\n\n")
	if b, err := os.ReadFile(filepath.Join(res, "copy-manifest-F5.json")); err == nil {
		sb.WriteString("## Copy manifest\n\n```json\n" + string(b) + "\n```\n\n")
	}
	for _, cell := range []string{"F5_S-file", "F5_S-iso", "F5_T"} {
		fmt.Fprintf(&sb, "## %s\n\n### Controller timeline\n\n%s\n### Requester decision\n\n%s\n", cell, eventTimeline(loadEvents(res, cell), "agent_mode"), decisionSummary(firstDecision(res, cell)))
		for _, t := range loadTrace(res, cell) {
			if t["kind"] == "a2a_response" {
				sb.WriteString("### Evidence returned over A2A (first response)\n\n" + pretty(t["data"]) + "\n")
				break
			}
		}
	}
	return sb.String()
}

func relayPair(res string) string {
	var sb strings.Builder
	sb.WriteString("# Paired trace: live relay (F6) versus honest (F1), policy T and P\n\nB serves a copy of A's card, forwards the requester's fresh nonce to A over a real A2A client, and returns A's untouched response. The verifier's signer verdict is correct (A's enrolled AK signed), the endpoint is B, and the job token lands at B.\n\n")
	for _, cell := range []string{"F1_T", "F6_T", "F6_P"} {
		fmt.Fprintf(&sb, "## %s\n\n### Controller timeline (relay transcript)\n\n%s\n### Requester decision\n\n%s\n", cell, eventTimeline(loadEvents(res, cell), "agent_mode"), decisionSummary(firstDecision(res, cell)))
		for _, e := range loadEvents(res, cell) {
			if e.Kind == "relay_forwarded" {
				sb.WriteString("### Payload B forwarded (exactly what A returned)\n\n" + pretty(e.Data["payload"]) + "\n")
			}
		}
	}
	return sb.String()
}

func coseTamperPair(res string) string {
	var sb strings.Builder
	sb.WriteString("# Paired trace: PTV envelope tamper (F8), policy T versus P\n\nB relays the challenge to A and edits only the outer `timestamp` to now+60 s (still inside the 300 s window). The inner TPM quote bytes are identical before and after. T sees only the quote and accepts; P verifies the COSE_Sign1 over the whole response with A's enrolled AK and rejects with PTV_ERR_010 while the inner quote still verifies.\n\n")
	for _, cell := range []string{"F8_T", "F8_P"} {
		fmt.Fprintf(&sb, "## %s\n\n### Controller timeline\n\n%s\n### Requester decision\n\n%s\n", cell, eventTimeline(loadEvents(res, cell), "agent_mode"), decisionSummary(firstDecision(res, cell)))
		for _, e := range loadEvents(res, cell) {
			if e.Kind != "relay_forwarded" {
				continue
			}
			orig, _ := e.Data["original"].(map[string]any)
			edit, _ := e.Data["payload"].(map[string]any)
			if cell == "F8_P" && orig != nil {
				sb.WriteString("### COSE_Sign1 pair\n\n")
				for name, m := range map[string]map[string]any{"original (as signed by A's AK)": orig, "edited by B": edit} {
					var ev wire.Evidence
					wire.FromMap(m, &ev)
					b, _ := wire.UnB64(ev.COSESign1)
					env, err := ptv.Open(b)
					if err != nil {
						fmt.Fprintf(&sb, "* %s: undecodable (%v)\n", name, err)
						continue
					}
					te, _ := ptv.DecodeEvidence(env.Resp.Evidence)
					qh := ""
					if te != nil {
						qh = hex.EncodeToString(sha256b(te.Quoted))
					}
					fmt.Fprintf(&sb, "* **%s**: %d bytes, tagged=%v, attester_id=%s, nonce=%s…, timestamp=%s, signature=%s…, inner quote sha256=%s…\n", name, len(b), ptv.IsTaggedSign1(b), env.Resp.AttesterID, hex.EncodeToString(env.Resp.Nonce)[:16], env.Resp.Timestamp.UTC().Format("2006-01-02T15:04:05Z"), hex.EncodeToString(env.Msg.Signature)[:32], qh[:16])
				}
				sb.WriteString("\nBoth envelopes carry the same protected header, the same signature bytes and the same inner quote bytes; only the payload's `timestamp` differs. The verifier's `envelope.signature_valid_under_enrolled_ak` is false for the edited one; `quote` (verified independently) is fully valid for both.\n\n")
			}
			if cell == "F8_T" && orig != nil {
				sb.WriteString("### Unauthenticated outer field pair (T format)\n\n")
				fmt.Fprintf(&sb, "* original timestamp: `%v`\n* edited timestamp: `%v`\n* quote bytes identical: `%v`\n\n", orig["timestamp"], edit["timestamp"], fmt.Sprint(orig["quote"]) == fmt.Sprint(edit["quote"]))
			}
		}
	}
	return sb.String()
}

func sha256b(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
