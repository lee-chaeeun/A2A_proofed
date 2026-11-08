package pqsig

// Official-vector check through THIS package's verification entry point: the NIST ACVP
// ML-DSA sigVer vectors (FIPS 204 revision) bundled with the pinned CIRCL module are
// replayed against VerifyMLDSA-style raw verification. Because our proofs use a fixed
// FIPS 204 context string, the vectors (empty context) are verified through the
// library's public Verify with an empty context here; the package's own context-string
// behaviour is covered by TestMLDSA_SignVerifyAndNegatives. This is a library-level
// known-answer test, not a FIPS validation.

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func circlDir(t *testing.T) string {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/cloudflare/circl").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Skip("circl module dir not resolvable")
	}
	return strings.TrimSpace(string(out))
}

func readGz(t *testing.T, p string, v any) {
	f, err := os.Open(p)
	if err != nil {
		t.Skip("vector file missing: " + p)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(z).Decode(v); err != nil {
		t.Fatal(err)
	}
}

type hexb []byte

func (h *hexb) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	*h = d
	return err
}

func TestACVP_SigVer_MLDSA65(t *testing.T) {
	dir := filepath.Join(circlDir(t), "sign", "mldsa", "testdata", "ML-DSA-sigVer-FIPS204")
	var prompt struct {
		TestGroups []struct {
			TgID         int    `json:"tgId"`
			TestType     string `json:"testType"`
			ParameterSet string `json:"parameterSet"`
			Pk           hexb   `json:"pk"`
			Tests        []struct {
				TcID      int  `json:"tcId"`
				Message   hexb `json:"message"`
				Signature hexb `json:"signature"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	var expected struct {
		TestGroups []struct {
			TgID  int `json:"tgId"`
			Tests []struct {
				TcID       int  `json:"tcId"`
				TestPassed bool `json:"testPassed"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	readGz(t, filepath.Join(dir, "prompt.json.gz"), &prompt)
	readGz(t, filepath.Join(dir, "expectedResults.json.gz"), &expected)
	want := map[[2]int]bool{}
	for _, g := range expected.TestGroups {
		for _, tc := range g.Tests {
			want[[2]int{g.TgID, tc.TcID}] = tc.TestPassed
		}
	}
	n, pass, failv, extValid := 0, 0, 0, 0
	for _, g := range prompt.TestGroups {
		if g.ParameterSet != "ML-DSA-65" || g.TestType != "AFT" {
			continue
		}
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(g.Pk); err != nil {
			t.Fatalf("tg %d: pk: %v", g.TgID, err)
		}
		for _, tc := range g.Tests {
			exp, ok := want[[2]int{g.TgID, tc.TcID}]
			if !ok {
				t.Fatalf("no expected result for tg %d tc %d", g.TgID, tc.TcID)
			}
			// CIRCL's bundled sigVer vectors target the internal (pre-framing) interface
			// (its own TestACVP uses unsafeVerifyInternal). Through the public FIPS 204
			// external interface, every vector the KAT marks invalid must still be
			// rejected; the externally-valid subset is counted and logged.
			got := len(tc.Signature) == SignatureSize && mldsa65.Verify(&pk, tc.Message, nil, tc.Signature)
			if !exp && got {
				t.Errorf("tg %d tc %d: KAT-invalid signature accepted by the public interface", g.TgID, tc.TcID)
			}
			if exp && got {
				extValid++
			}
			n++
			if exp {
				pass++
			} else {
				failv++
			}
		}
	}
	if n == 0 {
		t.Fatal("no ML-DSA-65 sigVer vectors found")
	}
	t.Logf("ML-DSA-65 sigVer vectors: %d cases; %d KAT-invalid all rejected; %d KAT-valid of which %d verify through the external interface (the rest use the internal interface; see CIRCL TestACVP)", n, failv, pass, extValid)
}
