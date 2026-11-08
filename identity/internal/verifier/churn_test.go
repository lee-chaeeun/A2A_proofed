package verifier

// [NETWORKED] A small, declared, reproducible connection-churn budget for the bound
// +cb policy (the randomized release-race trials cover the unbound proof policies).
// 60 trials: in half, the proof connection is closed before dispatch (churn); each
// trial's outcome is counted separately. T+cb shares this exact binding/dispatch
// path (verified by the deterministic V-fixtures and the binding regressions); this
// test exercises it concurrently over real TLS with the software S-env+cb proof.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestChurn_BoundPolicyConcurrency(t *testing.T) {
	const trials = 60 // declared budget, fixed and reproducible
	k := newKit(t)
	mk := func(label string) *senvServer {
		return &senvServer{label: label, sisoKey: k.siso, sisoKID: "A-siso-k1", attester: "dep-A", audience: DefaultAudience, received: make(chan string, trials*2)}
	}
	aSrv, bSrv := mk("A"), mk("B")
	aTS := startTLSA2A(t, aSrv, "https://a.a2aid.test:9443", k.cardKey(), "A-card-k1")
	bTS := startTLSA2A(t, bSrv, "https://a.a2aid.test:9443", k.cardKey(), "A-card-k1")
	cert := testCertFor(t, "a.a2aid.test")
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	aTS.TLS.Certificates = []tls.Certificate{cert}
	bTS.TLS.Certificates = []tls.Certificate{cert}
	aTS.StartTLS()
	bTS.StartTLS()
	defer aTS.Close()
	defer bTS.Close()
	aAddr, bAddr := aTS.Listener.Addr().String(), bTS.Listener.Addr().String()
	k.r.Reg.Deployments["A"].TLSName = "a.a2aid.test"

	var mu sync.Mutex
	var attempts, appraisalsAccepted, dispatches, deliveredToA, refusedReconnect, errors, bReceipts int
	var wg sync.WaitGroup
	for i := 0; i < trials; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			churn := i%2 == 0 // deterministic: even trials close the proof connection
			r := New(k.r.Reg, nil, nil)
			r.RootCAs = pool
			resolver := map[string]string{"a.a2aid.test:9443": aAddr}
			r.Resolver = resolver
			var rmu sync.Mutex
			r.Hook = func(stage string, d *Decision) {
				if stage != "after-appraise" || !d.Accept || !churn {
					return
				}
				for _, c := range d.conns.all() {
					c.Close()
				}
				rmu.Lock()
				resolver["a.a2aid.test:9443"] = bAddr
				rmu.Unlock()
			}
			d, err := r.Run(context.Background(), "S-env+cb", "https://a.a2aid.test:9443", "A", nil)
			mu.Lock()
			attempts++
			if err == nil && d.Accept {
				appraisalsAccepted++
			}
			if d.DispatchAttempted {
				dispatches++
			}
			if d.JobReleased && d.JobConnReused {
				deliveredToA++
			}
			if d.JobError != "" && !d.JobReleased {
				refusedReconnect++
			}
			if err != nil {
				errors++
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	// drain B receipts
	time.Sleep(300 * time.Millisecond)
	for {
		select {
		case <-bSrv.received:
			bReceipts++
			continue
		default:
		}
		break
	}
	report := fmt.Sprintf("churn trials=%d attempts=%d appraisals_accepted=%d dispatches_attempted=%d delivered_to_A=%d reconnect_refused=%d run_errors=%d B_receipts=%d",
		trials, attempts, appraisalsAccepted, dispatches, deliveredToA, refusedReconnect, errors, bReceipts)
	t.Log(report)
	if bReceipts != 0 {
		t.Fatalf("a job reached B under churn: %s", report)
	}
	if deliveredToA != trials/2 {
		t.Fatalf("expected the %d non-churn trials to deliver to A: %s", trials/2, report)
	}
	if refusedReconnect != trials/2 {
		t.Fatalf("expected the %d churn trials to refuse the reconnect: %s", trials/2, report)
	}
}
