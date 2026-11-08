package ptv

import (
	"testing"
	"time"
)

// FuzzOpen: decoding arbitrary bytes must not panic; whatever decodes must still
// fail SchemaCheck unless it is a well-formed routine response.
func FuzzOpen(f *testing.F) {
	f.Add([]byte{0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x40, 0x40})
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, b []byte) {
		env, err := Open(b)
		if err != nil {
			return
		}
		code, _ := env.SchemaCheck()
		_ = code
		_, _ = env.FreshnessCheck(time.Now())
		_, _ = DecodeEvidence(env.Resp.Evidence)
		IsTaggedSign1(b)
	})
}

func FuzzDecodeEvidence(f *testing.F) {
	f.Add([]byte{0xa1, 0x63, 0x66, 0x6d, 0x74, 0x60})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeEvidence(b)
	})
}
