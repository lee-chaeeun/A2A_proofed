package wire

import "testing"

func FuzzNormalizeURL(f *testing.F) {
	f.Add("http://A.a2aid.test:80/")
	f.Add("https://x:443")
	f.Fuzz(func(t *testing.T, s string) {
		n, err := NormalizeURL(s)
		if err != nil {
			return
		}
		// idempotent
		n2, err := NormalizeURL(n)
		if err != nil || n2 != n {
			t.Fatalf("not idempotent: %q -> %q -> %q (%v)", s, n, n2, err)
		}
	})
}

func FuzzParsePolicy(f *testing.F) {
	f.Add("T+cb")
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParsePolicy(s)
		if err != nil {
			return
		}
		if p.CB && !p.TLS || p.TLS && !p.URL {
			t.Fatal("implication broken")
		}
		if _, err := ParsePolicy(p.String()); err != nil {
			t.Fatalf("round trip %q -> %q", s, p.String())
		}
	})
}
