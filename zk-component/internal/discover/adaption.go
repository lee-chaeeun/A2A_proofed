package discover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Adaption is a minimal client for the documented endpoints:
//
//	GET  /api/v1/models            (discovery)
//	POST /api/v1/responses         (inference; NO documented cost fields)
//	POST /api/v1/datasets/invent   (estimate=true is free and returns credits)
//
// The API key is read from ADAPTION_API_KEY and never printed or logged.
type Adaption struct {
	Base string
	key  string
	HTTP *http.Client
	Org  string
}

const DefaultBase = "https://api.prod.adaptionlabs.ai"

var ErrNoKey = errors.New("ADAPTION_API_KEY not set")

func NewAdaption() (*Adaption, error) {
	k := strings.TrimSpace(os.Getenv("ADAPTION_API_KEY"))
	if k == "" {
		return nil, ErrNoKey
	}
	base := os.Getenv("ADAPTION_API_BASE")
	if base == "" {
		base = DefaultBase
	}
	return &Adaption{Base: base, key: k, HTTP: &http.Client{Timeout: 120 * time.Second}, Org: os.Getenv("ADAPTION_ORG_ID")}, nil
}

func (a *Adaption) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.key)
	req.Header.Set("Content-Type", "application/json")
	if a.Org != "" {
		req.Header.Set("X-Organization-Id", a.Org)
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, truncate(string(rb), 400))
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

type Model struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
	OwnedBy     string `json:"owned_by"`
	Shutdown    string `json:"shutdown_date,omitempty"`
}

// Models lists the hosted models the organization can use. Nothing is hard-coded:
// a model identifier must come from this list (or the user) to be used.
func (a *Adaption) Models(ctx context.Context) ([]Model, error) {
	var out struct {
		Data []Model `json:"data"`
	}
	err := a.do(ctx, "GET", "/api/v1/models", nil, &out)
	return out.Data, err
}

// InventEstimate prices a dataset invention without creating or charging anything.
type InventEstimate struct {
	Estimate         bool `json:"estimate"`
	EstimatedCredits int  `json:"estimated_credits"`
	AvailableCredits int  `json:"available_credits"`
}

func (a *Adaption) InventEstimate(ctx context.Context, rows int, prompt string) (*InventEstimate, error) {
	var out InventEstimate
	err := a.do(ctx, "POST", "/api/v1/datasets/invent", map[string]any{"rows": rows, "dataset_prompt": prompt, "estimate": true}, &out)
	return &out, err
}

// Respond calls the Responses API ONCE with memory disabled and no tools. It is
// only reachable through the CLI when the operator has supplied a verified
// per-token price (see cmd); usage tokens are returned so a ledger can convert
// them with that price.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

func (a *Adaption) Respond(ctx context.Context, model, instructions, input string, maxOut int, temperature float64) (string, Usage, error) {
	var out struct {
		Status     string `json:"status"`
		OutputText string `json:"output_text"`
		Usage      Usage  `json:"usage"`
		Error      any    `json:"error"`
	}
	body := map[string]any{"model": model, "instructions": instructions, "input": input, "agentic_memory": false, "store": false, "max_output_tokens": maxOut, "temperature": temperature, "tool_choice": "none"}
	if err := a.do(ctx, "POST", "/api/v1/responses", body, &out); err != nil {
		return "", Usage{}, err
	}
	if out.Status != "completed" {
		return out.OutputText, out.Usage, fmt.Errorf("response status %s: %v", out.Status, out.Error)
	}
	return out.OutputText, out.Usage, nil
}

// ModelPlanner asks a model for plans in the fixed JSON schema. Frozen prompt,
// temperature and token limit; the model sees the schema and the capability
// statement, never keys or traces.
type ModelPlanner struct {
	API         *Adaption
	Model       string
	Temperature float64
	MaxOut      int
	Caps        Capabilities
	Family      string // "development" or "heldout": different seed families, kept apart
	OnUsage     func(Usage)
}

const plannerInstructions = `You are a protocol test designer. You will propose MUTATION PLANS against a PTV draft-01 routine-mode PTV_PROVE_RESP (CBOR map fields: ptv_version "1.1", msg_type 2, nonce bstr, attester_id tstr, triage_band 0, evidence bstr, timestamp tag1 epoch) carried in a COSE_Sign1 and verified by a relying party that: resolves attester_id through an enrollment registry, verifies the COSE signature with the enrolled key, checks schema (routine band: evidence present and non-empty, proof absent), nonce equality with the issued nonce, timestamp within 300 s, then independently verifies the embedded TPM quote (magic, type QUOTE, ECDSA/SHA-256, signature under the enrolled AK, qualifiedSigner, extraData == nonce, PCR selection sha256:16, pcrDigest == sha256(reference)).
You may ONLY use these operations (JSON objects): drop_field{field}, set_null{field}, set_empty_bstr{field}, set_text{field,value}, set_int{field,int_value}, add_proof{}, shift_timestamp{int_value seconds}, replace_nonce{}, truncate_evidence{int_value}, flip_byte{target in envelope|evidence|quote|quote_sig, int_value}, sign_with{value enrolled|unenrolled}, quote_sign_with{value enrolled|unenrolled}, quote_nonce{value issued|random}, quote_pcr{value reference|other}, quote_magic{value tpm_generated|zero}, quote_type{value quote|certify}, quote_hash{value sha256|sha1}, evidence_format{value}, wrong_attester{value dep-B|unknown}, envelope_untagged{}, alg_header{value ES256|ES384|none}.
Do NOT fabricate signed bytes or claim success. Output ONLY a JSON array of plans: [{"id":"...","family":"...","rationale":"...","mutations":[...],"permissions":["enrolled_signer","unenrolled_keys"]}]. Prefer plans that combine mutations in ways a naive verifier might accept.`

func (m *ModelPlanner) Name() string { return "adaption:" + m.Model }

func (m *ModelPlanner) Propose(n int) ([]Plan, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	input := fmt.Sprintf("Capabilities granted: enrolled_signer=%v unenrolled_keys=%v. Mechanism family focus: %s. Propose %d distinct plans.", m.Caps.EnrolledSigner, m.Caps.Unenrolled, m.Family, n)
	text, usage, err := m.API.Respond(ctx, m.Model, plannerInstructions, input, m.MaxOut, m.Temperature)
	if m.OnUsage != nil {
		m.OnUsage(usage)
	}
	if err != nil {
		return nil, err
	}
	text = strings.TrimSpace(text)
	if i := strings.Index(text, "["); i >= 0 {
		text = text[i:]
	}
	if j := strings.LastIndex(text, "]"); j >= 0 {
		text = text[:j+1]
	}
	var plans []Plan
	if err := json.Unmarshal([]byte(text), &plans); err != nil {
		return nil, fmt.Errorf("model output is not a plan array: %w", err)
	}
	return plans, nil
}
