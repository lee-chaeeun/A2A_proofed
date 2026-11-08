package pqsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sort"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"a2aid/internal/pqdev"
)

// Stat is a small declared-sample timing summary (microseconds).
type Stat struct {
	Samples  int     `json:"samples"`
	MedianUS float64 `json:"median_us"`
	MinUS    float64 `json:"min_us"`
	MaxUS    float64 `json:"max_us"`
}

func stat(d []time.Duration) Stat {
	s := make([]float64, len(d))
	for i, x := range d {
		s[i] = float64(x.Microseconds())
	}
	sort.Float64s(s)
	if len(s) == 0 {
		return Stat{}
	}
	return Stat{Samples: len(s), MedianUS: s[len(s)/2], MinUS: s[0], MaxUS: s[len(s)-1]}
}

// Bench holds the measured sizes and timings of one host.
type Bench struct {
	Host                 string         `json:"host_note"`
	Sizes                map[string]int `json:"sizes_bytes"`
	MLDSAKeyGen          Stat           `json:"mldsa65_keygen"`
	MLDSASign            Stat           `json:"mldsa65_sign"`
	MLDSAVerify          Stat           `json:"mldsa65_verify"`
	ECKeyGen             Stat           `json:"p256_keygen"`
	ECSign               Stat           `json:"p256_sign"`
	ECVerify             Stat           `json:"p256_verify"`
	DeviceSignBridgeWall Stat           `json:"device_sign_bridge_wall"`  // process start to exit (bridge + socket + emulator)
	DeviceSignCommands   Stat           `json:"device_sign_tpm_commands"` // sum of the bridge's per-command times (ReadPublic + SignSequenceStart/Complete)
	DeviceSignComplete   Stat           `json:"device_sign_sequence_complete_only"`
	DeviceVerifyHost     Stat           `json:"device_signature_verify_host_circl"`
	DeviceNote           string         `json:"device_note,omitempty"`
}

// RunBench measures n samples of each operation over a representative context.
func RunBench(n int, dev *pqdev.Device) (*Bench, error) {
	b := &Bench{Sizes: map[string]int{}, Host: "single host, CPU only; emulator timings are not physical TPM timings; microbenchmarks are not agent throughput"}
	ctx := &Context{V: Format, Role: Role, Policy: "PQ-device+cb", Alg: AlgMLDSA, KID: "A-pqdev-k1", Expected: "dep-A", Requester: "requester:a2aid-lab", Action: "release-synthetic-job", Nonce: make([]byte, 32), Expiry: time.Now().Unix() + 120, Session: "c2Vzc2lvbi1ub25jZS1iYXNlNjQtMzItYnl0ZXM=", Exporter: make([]byte, 32)}
	msg, err := Encode(ctx)
	if err != nil {
		return nil, err
	}
	b.Sizes["context_cbor"] = len(msg)
	b.Sizes["mldsa65_public_key"] = PublicKeySize
	b.Sizes["mldsa65_signature"] = SignatureSize
	b.Sizes["p256_public_key_uncompressed"] = 65
	b.Sizes["p256_signature_raw"] = 64
	var kg, sg, vf []time.Duration
	for i := 0; i < n; i++ {
		t0 := time.Now()
		pk, sk, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		kg = append(kg, time.Since(t0))
		t1 := time.Now()
		sig, err := SignMLDSA(sk, msg)
		if err != nil {
			return nil, err
		}
		sg = append(sg, time.Since(t1))
		t2 := time.Now()
		if !VerifyMLDSA(MLDSAPublicBytes(pk), msg, sig) {
			return nil, err
		}
		vf = append(vf, time.Since(t2))
	}
	b.MLDSAKeyGen, b.MLDSASign, b.MLDSAVerify = stat(kg), stat(sg), stat(vf)
	kg, sg, vf = nil, nil, nil
	for i := 0; i < n; i++ {
		t0 := time.Now()
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		kg = append(kg, time.Since(t0))
		t1 := time.Now()
		sig, err := SignES256(sk, msg)
		if err != nil {
			return nil, err
		}
		sg = append(sg, time.Since(t1))
		t2 := time.Now()
		VerifyES256(&sk.PublicKey, msg, sig)
		vf = append(vf, time.Since(t2))
	}
	b.ECKeyGen, b.ECSign, b.ECVerify = stat(kg), stat(sg), stat(vf)
	if dev != nil {
		_, pub, err := dev.Public(context.Background())
		if err != nil {
			b.DeviceNote = "device unavailable: " + err.Error()
			return b, nil
		}
		var wall, cmds, complete, hv []time.Duration
		for i := 0; i < n; i++ {
			r, sig, err := dev.Sign(context.Background(), msg, []byte(CtxString))
			if err != nil {
				b.DeviceNote = "device sign failed: " + err.Error()
				break
			}
			wall = append(wall, time.Duration(r.WallUS)*time.Microsecond)
			var sumUS, compUS int64
			for _, c := range r.Commands {
				if c.Name != "Init(Startup/SelfTest)" {
					sumUS += c.US
				}
				if c.Name == "TPM2_SignSequenceComplete" {
					compUS = c.US
				}
			}
			cmds = append(cmds, time.Duration(sumUS)*time.Microsecond)
			complete = append(complete, time.Duration(compUS)*time.Microsecond)
			t := time.Now()
			if !VerifyMLDSA(pub, msg, sig) {
				b.DeviceNote = "device signature did not verify on the host"
				break
			}
			hv = append(hv, time.Since(t))
		}
		b.DeviceSignBridgeWall, b.DeviceSignCommands, b.DeviceSignComplete, b.DeviceVerifyHost = stat(wall), stat(cmds), stat(complete), stat(hv)
	}
	return b, nil
}
