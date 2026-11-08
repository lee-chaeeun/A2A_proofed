package senv

import (
	"testing"
	"time"
)

func FuzzOpen(f *testing.F) {
	f.Add([]byte{0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x40, 0x40})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := Open(b)
		if err != nil {
			return
		}
		_ = e.Check("dep-A", []byte("n"), "a", "aud", "S-env", time.Now(), time.Minute)
	})
}
